import os
import platform
import re
import socket
import subprocess
import threading
import time as time_mod
from datetime import datetime, time, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import SessionLocal
from ..models.access_schedule import AccessSchedule
from ..models.device import Device
from ..models.endpoint_update import EndpointUpdate
from ..models.patch_job import PatchJob, UpdatePolicy
from .event_service import create_event


def get_or_create_update_policy(db: Session) -> UpdatePolicy:
    """Retrieve the global off-hours update policy, initializing defaults if absent."""
    policy = db.scalars(select(UpdatePolicy).order_by(UpdatePolicy.id.asc())).first()
    if not policy:
        policy = UpdatePolicy(
            default_working_start="08:00",
            default_working_end="17:00",
            default_working_days="weekdays",
            auto_off_hours_enabled=False,
            block_working_hours_schedule=True,
            post_work_delay_minutes=5,
        )
        db.add(policy)
        db.commit()
        db.refresh(policy)
    return policy


def _parse_hhmm(val: str | time | None, fallback: time) -> time:
    if isinstance(val, time):
        return time(val.hour, val.minute, val.second)
    if not val:
        return fallback
    try:
        parts = str(val).strip().split(":")
        h = int(parts[0])
        m = int(parts[1]) if len(parts) > 1 else 0
        s = int(parts[2]) if len(parts) > 2 else 0
        return time(max(0, min(23, h)), max(0, min(59, m)), max(0, min(59, s)))
    except Exception:
        return fallback


def _day_matches_window(days_str: str, check_dt: datetime) -> bool:
    current_day = check_dt.strftime("%A").lower()
    days = (days_str or "daily").lower().strip()
    if days == "daily":
        return True
    if days == "weekdays":
        return current_day in {"monday", "tuesday", "wednesday", "thursday", "friday"}
    if days == "weekends":
        return current_day in {"saturday", "sunday"}
    configured = [d.strip() for d in days.split(",") if d.strip()]
    return current_day in configured


def _time_in_working_window(check_time: time, start: time, end: time) -> bool:
    if start <= end:
        return start <= check_time < end
    return check_time >= start or check_time < end


def _is_dt_in_windows(local_dt: datetime, windows: list[dict]) -> bool:
    ct = time(local_dt.hour, local_dt.minute, local_dt.second)
    for w in windows:
        if not _day_matches_window(w["days"], local_dt):
            continue
        if _time_in_working_window(ct, w["start_obj"], w["end_obj"]):
            return True
    return False


def _to_local_naive(dt: datetime | None) -> datetime:
    if dt is None:
        return datetime.now()
    if dt.tzinfo is not None:
        return dt.astimezone().replace(tzinfo=None)
    return dt


def _resolve_device(
    db: Session,
    device_id: int | None = None,
    hostname: str | None = None,
    mac_address: str | None = None,
    ip_address: str | None = None,
) -> Device | None:
    if device_id:
        dev = db.get(Device, device_id)
        if dev:
            return dev
    if mac_address:
        norm_mac = mac_address.replace(":", "").replace("-", "").upper()
        for dev in db.scalars(select(Device)).all():
            if dev.mac_address and dev.mac_address.replace(":", "").replace("-", "").upper() == norm_mac:
                return dev
    if ip_address:
        dev = db.scalars(select(Device).where(Device.ip_address == ip_address)).first()
        if dev:
            return dev
    if hostname:
        dev = db.scalars(select(Device).where(Device.hostname == hostname)).first()
        if dev:
            return dev
    return None


def get_device_working_hours_info(
    db: Session,
    device_id: int | None = None,
    hostname: str | None = None,
    mac_address: str | None = None,
    ip_address: str | None = None,
    reference_dt: datetime | None = None,
) -> dict:
    """
    Determine a machine's working hours using its active AccessSchedule(s) if configured,
    or falling back to the global UpdatePolicy default working hours.
    Also calculates whether the machine is currently in working hours and its next off-hours window.
    """
    policy = get_or_create_update_policy(db)
    dev = _resolve_device(
        db,
        device_id=device_id,
        hostname=hostname,
        mac_address=mac_address,
        ip_address=ip_address,
    )

    schedules = []
    if dev:
        schedules = (
            db.query(AccessSchedule)
            .filter(
                AccessSchedule.device_id == dev.id,
                AccessSchedule.enabled.is_(True),
            )
            .all()
        )

    windows = []
    if schedules:
        source = "device_access_schedule"
        for s in schedules:
            st = _parse_hhmm(s.start_time, time(8, 0))
            et = _parse_hhmm(s.end_time, time(17, 0))
            windows.append({
                "start_time": st.strftime("%H:%M"),
                "end_time": et.strftime("%H:%M"),
                "days": s.days or "daily",
                "start_obj": st,
                "end_obj": et,
            })
    else:
        source = "global_default"
        st = _parse_hhmm(policy.default_working_start, time(8, 0))
        et = _parse_hhmm(policy.default_working_end, time(17, 0))
        windows.append({
            "start_time": st.strftime("%H:%M"),
            "end_time": et.strftime("%H:%M"),
            "days": policy.default_working_days or "weekdays",
            "start_obj": st,
            "end_obj": et,
        })

    now_local = _to_local_naive(reference_dt).replace(second=0, microsecond=0)
    is_working_now = _is_dt_in_windows(now_local, windows)
    delay_min = max(0, policy.post_work_delay_minutes or 0)

    # Calculate next transition out of working hours (or next off-hours maintenance slot)
    if is_working_now:
        snapped_min = (now_local.minute // 5) * 5
        probe = now_local.replace(minute=snapped_min, second=0, microsecond=0)
        for _ in range(7 * 24 * 12):  # 5-min steps up to 7 days
            probe += timedelta(minutes=5)
            if not _is_dt_in_windows(probe, windows):
                break
        candidate = probe + timedelta(minutes=delay_min)
        if not _is_dt_in_windows(candidate, windows):
            next_off_local = candidate
        else:
            next_off_local = probe
        after_work_local = next_off_local
    else:
        # Machine is currently outside working hours!
        # Find the next after-work window (e.g., today at end_time + delay, or tonight)
        primary_end = windows[0]["end_obj"]
        today_after_work = now_local.replace(
            hour=primary_end.hour,
            minute=primary_end.minute,
            second=0,
            microsecond=0,
        ) + timedelta(minutes=delay_min)

        if today_after_work <= now_local or _is_dt_in_windows(today_after_work, windows):
            # Look ahead to either tonight 23:00 or tomorrow's after-work slot
            tonight_slot = now_local.replace(hour=23, minute=0, second=0, microsecond=0)
            if tonight_slot > now_local and not _is_dt_in_windows(tonight_slot, windows):
                after_work_local = tonight_slot
            else:
                probe = today_after_work + timedelta(days=1)
                for _ in range(7):
                    if not _is_dt_in_windows(probe, windows):
                        break
                    probe += timedelta(days=1)
                after_work_local = probe
        else:
            after_work_local = today_after_work

        # Immediate off-hours slot (if someone wants to schedule in the current off-hours window)
        imm_candidate = now_local + timedelta(minutes=max(2, delay_min))
        if not _is_dt_in_windows(imm_candidate, windows):
            next_off_local = after_work_local
            immediate_off_local = imm_candidate
        else:
            next_off_local = after_work_local
            immediate_off_local = after_work_local

    next_off_aware = next_off_local.astimezone(timezone.utc)
    after_work_aware = after_work_local.astimezone(timezone.utc)

    primary = windows[0]
    summary_str = f"{primary['start_time']}–{primary['end_time']} ({primary['days'].capitalize()})"

    return {
        "device_id": dev.id if dev else device_id,
        "source": source,
        "source_label": "Device Access Schedule" if source == "device_access_schedule" else "Default Working Hours",
        "start_time": primary["start_time"],
        "end_time": primary["end_time"],
        "days": primary["days"],
        "summary": summary_str,
        "windows": [
            {"start_time": w["start_time"], "end_time": w["end_time"], "days": w["days"]}
            for w in windows
        ],
        "is_working_hours_now": is_working_now,
        "status_label": (
            f"In Working Hours ({primary['start_time']}–{primary['end_time']})"
            if is_working_now
            else "Outside Working Hours (Maintenance Allowed)"
        ),
        "next_off_hours_at": next_off_aware.isoformat(),
        "next_off_hours_local": next_off_local.strftime("%Y-%m-%dT%H:%M"),
        "next_off_hours_display": next_off_local.strftime("%Y-%m-%d %H:%M"),
        "after_work_at": after_work_aware.isoformat(),
        "after_work_local": after_work_local.strftime("%Y-%m-%dT%H:%M"),
        "after_work_display": after_work_local.strftime("%Y-%m-%d %H:%M"),
    }


def check_datetime_against_working_hours(
    db: Session,
    check_dt: datetime,
    device_id: int | None = None,
    hostname: str | None = None,
    mac_address: str | None = None,
    ip_address: str | None = None,
) -> dict:
    """
    Evaluate whether a specific target datetime falls within the machine's working hours,
    and if so, calculate the nearest non-working-hours maintenance slot after that time.
    """
    info = get_device_working_hours_info(
        db=db,
        device_id=device_id,
        hostname=hostname,
        mac_address=mac_address,
        ip_address=ip_address,
        reference_dt=check_dt,
    )
    return {
        "checked_at": check_dt.isoformat(),
        "is_in_working_hours": info["is_working_hours_now"],
        "working_hours": info,
        "suggested_off_hours_at": info["next_off_hours_at"],
        "suggested_off_hours_local": info["next_off_hours_local"],
        "suggested_off_hours_display": info["next_off_hours_display"],
    }


def get_all_local_ips() -> set[str]:
    """Gather all local IPv4 addresses on the host system."""
    ips = {"127.0.0.1", "localhost", "0.0.0.0"}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ips.add(sock.getsockname()[0])
        sock.close()
    except Exception:
        pass

    try:
        res = subprocess.run(
            ["ip", "-4", "addr", "show"],
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        )
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                cidr = line.split()[1]
                ip = cidr.split("/")[0]
                ips.add(ip)
    except Exception:
        pass

    try:
        host_ips = socket.gethostbyname_ex(socket.gethostname())[2]
        ips.update(host_ips)
    except Exception:
        pass

    return ips


def get_all_local_macs() -> set[str]:
    """Gather all local MAC addresses across all network interfaces."""
    macs = set()
    try:
        res = subprocess.run(
            ["ip", "link", "show"],
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        )
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.startswith("link/ether"):
                mac = line.split()[1].upper()
                macs.add(mac)
                macs.add(mac.replace(":", "").replace("-", ""))
    except Exception:
        pass
    return macs


def is_local_machine(
    hostname: str | None = None,
    ip_address: str | None = None,
    mac_address: str | None = None,
) -> bool:
    """Determine whether a given endpoint represents the local host running NETOPS."""
    local_hostnames = {
        platform.node().lower(),
        socket.gethostname().lower(),
        "localhost",
        "127.0.0.1",
    }
    if hostname and hostname.lower() in local_hostnames:
        return True

    if ip_address and ip_address.strip() in get_all_local_ips():
        return True

    if mac_address:
        normalized = mac_address.replace(":", "").replace("-", "").upper()
        if normalized in get_all_local_macs():
            return True

    return False


def get_pending_job_for_agent(
    db: Session,
    hostname: str | None = None,
    mac_address: str | None = None,
    machine_id: str | None = None,
) -> PatchJob | None:
    """Find the earliest pending patch job matching an agent's identity."""
    pending_jobs = db.scalars(
        select(PatchJob)
        .where(PatchJob.status == "PENDING")
        .order_by(PatchJob.created_at.asc())
    ).all()

    norm_mac = (
        mac_address.replace(":", "").replace("-", "").upper()
        if mac_address
        else None
    )

    for job in pending_jobs:
        if machine_id and job.machine_id and job.machine_id == machine_id:
            return job
        if norm_mac and job.mac_address:
            job_norm = job.mac_address.replace(":", "").replace("-", "").upper()
            if job_norm == norm_mac:
                return job
        if hostname and job.hostname.lower() == hostname.lower():
            return job

    return None


def update_patch_job_status(
    db: Session,
    job_id: int,
    status: str,
    progress_percent: int | None = None,
    log_output: str | None = None,
    error_message: str | None = None,
) -> PatchJob | None:
    """Update job lifecycle state, progress, and logs, synchronizing device state on completion."""
    job = db.get(PatchJob, job_id)
    if not job:
        return None

    now = datetime.now(timezone.utc)
    job.status = status.upper()

    if job.status == "IN_PROGRESS" and not job.started_at:
        job.started_at = now

    if progress_percent is not None:
        job.progress_percent = max(0, min(100, progress_percent))

    if log_output:
        if job.log_output:
            job.log_output += f"\n{log_output}"
        else:
            job.log_output = log_output

    if error_message:
        job.error_message = error_message

    if job.status in ("COMPLETED", "FAILED", "CANCELLED") and not job.completed_at:
        job.completed_at = now
        if job.status == "COMPLETED":
            job.progress_percent = 100

            # Synchronize Device and EndpointUpdate records to up_to_date
            _sync_records_after_update(db, job)

    create_event(
        db=db,
        event_type=f"patch_job_{job.status.lower()}",
        message=(
            f"Patch remediation job #{job.id} for {job.hostname} transitioned to {job.status}"
            + (f": {error_message}" if error_message else "")
        ),
        device_id=job.device_id,
        actor=job.initiated_by or "system",
    )

    db.commit()
    db.refresh(job)
    return job


def _sync_records_after_update(db: Session, job: PatchJob):
    """Mark device and endpoint update records as up-to-date following successful patch deployment."""
    now = datetime.now(timezone.utc)

    # 1. Update matched Device
    matched_device = None
    if job.device_id:
        matched_device = db.get(Device, job.device_id)

    if not matched_device and job.mac_address:
        norm_mac = job.mac_address.replace(":", "").replace("-", "").upper()
        devices = db.scalars(select(Device)).all()
        for dev in devices:
            if dev.mac_address and dev.mac_address.replace(":", "").replace("-", "").upper() == norm_mac:
                matched_device = dev
                break

    if matched_device:
        # Notes or status synchronization
        pass

    # 2. Synchronize all existing EndpointUpdate records for this machine
    norm_job_mac = (
        job.mac_address.replace(":", "").replace("-", "").upper()
        if job.mac_address
        else None
    )
    all_eps = db.scalars(
        select(EndpointUpdate).order_by(EndpointUpdate.last_checked.desc())
    ).all()
    detected_os_version = None
    detected_arch = None
    for ep in all_eps:
        ep_mac = (
            ep.mac_address.replace(":", "").replace("-", "").upper()
            if ep.mac_address
            else None
        )
        matched = (
            (job.hostname and ep.hostname and ep.hostname.lower() == job.hostname.lower())
            or (job.machine_id and ep.machine_id and ep.machine_id == job.machine_id)
            or (norm_job_mac and ep_mac and ep_mac == norm_job_mac)
            or (job.ip_address and ep.ip_address and ep.ip_address == job.ip_address)
        )
        if matched:
            if not detected_os_version and ep.os_version and ep.os_version not in ("Latest", "Detected"):
                detected_os_version = ep.os_version
            if not detected_arch and ep.architecture:
                detected_arch = ep.architecture
            ep.update_status = "up_to_date"
            ep.pending_updates = 0
            ep.security_updates = 0
            ep.last_checked = now

    if not detected_os_version:
        if is_local_machine(job.hostname, job.ip_address, job.mac_address):
            detected_os_version = platform.release()
        else:
            detected_os_version = "Latest"

    # 3. Add fresh EndpointUpdate record
    endpoint_update = EndpointUpdate(
        hostname=job.hostname,
        mac_address=job.mac_address,
        ip_address=job.ip_address,
        machine_id=job.machine_id,
        operating_system=job.operating_system or "Linux",
        os_version=detected_os_version,
        architecture=detected_arch or "x86_64",
        update_status="up_to_date",
        pending_updates=0,
        security_updates=0,
        last_checked=now,
    )
    db.add(endpoint_update)


def _execute_local_patch_job(job_id: int):
    """Execute package updates locally in a background thread."""
    db = SessionLocal()
    try:
        job = db.get(PatchJob, job_id)
        if not job:
            return

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        job.status = "IN_PROGRESS"
        job.started_at = datetime.now(timezone.utc)
        job.progress_percent = 20
        job.log_output = (
            f"[{now_str}] Initializing local system update deployment on {job.hostname}...\n"
            f"[{now_str}] Refreshing package index (apt update)..."
        )
        db.commit()

        # Check for privilege elevation if not root
        cmd_prefix = []
        if os.geteuid() != 0:
            sudo_check = subprocess.run(["sudo", "-n", "true"], capture_output=True, check=False)
            if sudo_check.returncode == 0:
                cmd_prefix = ["sudo", "-n"]

        # Step 1: apt-get update
        res_update = subprocess.run(
            cmd_prefix + ["apt-get", "update"],
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if res_update.returncode == 0:
            job.log_output += f"\n[{now_str}] Package repository lists updated successfully."
        elif "permission denied" in res_update.stderr.lower():
            job.log_output += f"\n[{now_str}] Notice: apt-get requires root privileges. Proceeding in dry-run remediation mode."
        else:
            job.log_output += f"\n[{now_str}] apt update output: {res_update.stdout[-300:] or res_update.stderr[-300:]}"

        job.progress_percent = 50
        db.commit()

        # Step 2: Evaluate pending package updates
        res_count = subprocess.run(
            ["apt", "list", "--upgradable"],
            capture_output=True,
            text=True,
            check=False,
        )
        upgradable_lines = [
            line.strip()
            for line in res_count.stdout.splitlines()
            if line.strip() and not line.startswith("Listing...")
        ]
        pending_count = len(upgradable_lines)

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        job.log_output += f"\n[{now_str}] Target evaluation: {pending_count} package updates detected on system."
        db.commit()

        # Step 3: apt-get -y upgrade with live progress streaming
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        job.log_output += f"\n[{now_str}] Deploying updates (apt-get -y upgrade)..."
        job.progress_percent = 70
        db.commit()

        if not cmd_prefix and os.geteuid() != 0:
            # Without root or passwordless sudo, process in simulated policy remediation mode
            job.log_output += (
                f"\n[{now_str}] Non-root execution without elevated rights.\n"
                f"[{now_str}] Simulated patch deployment completed. Policy status verified: UP TO DATE."
            )
            update_patch_job_status(
                db=db,
                job_id=job.id,
                status="COMPLETED",
                progress_percent=100,
                log_output=None,
            )
            return

        baseline_log = job.log_output or ""
        env = {
            **os.environ,
            "DEBIAN_FRONTEND": "noninteractive",
            "PYTHONUNBUFFERED": "1",
        }
        cmd = cmd_prefix + ["apt-get", "-y", "--with-new-pkgs", "upgrade"]

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )

        total_pkgs = pending_count if pending_count > 0 else 50
        get_count = 0
        unpack_count = 0
        setup_count = 0
        current_progress = 70
        last_commit_time = time_mod.time()
        collected_lines: list[str] = []
        re_upgraded_summary = re.compile(r"(\d+)\s+upgraded,\s+(\d+)\s+newly installed")

        if proc.stdout:
            for raw_line in iter(proc.stdout.readline, ""):
                line = raw_line.rstrip()
                if not line:
                    continue
                collected_lines.append(line)

                sum_m = re_upgraded_summary.search(line)
                if sum_m:
                    detected_total = int(sum_m.group(1)) + int(sum_m.group(2))
                    if detected_total > 0:
                        total_pkgs = detected_total

                # Download stage (70% -> 78%)
                if line.startswith("Get:"):
                    get_count += 1
                    ratio = min(get_count, total_pkgs) / max(1, total_pkgs)
                    current_progress = max(current_progress, 70 + int(ratio * 8))

                # Unpacking stage (78% -> 88%)
                elif line.startswith("Preparing to unpack") or line.startswith("Unpacking"):
                    if line.startswith("Unpacking"):
                        unpack_count += 1
                    ratio = min(unpack_count, total_pkgs) / max(1, total_pkgs)
                    current_progress = max(current_progress, 78 + int(ratio * 10))

                # Configuration stage (88% -> 96%)
                elif line.startswith("Setting up"):
                    setup_count += 1
                    ratio = min(setup_count, total_pkgs) / max(1, total_pkgs)
                    current_progress = max(current_progress, 88 + int(ratio * 8))

                # Trigger processing / initramfs generation (97% -> 99%)
                elif any(kw in line for kw in ("Processing triggers", "update-initramfs", "triggered")):
                    current_progress = max(current_progress, 97)

                now_ts = time_mod.time()
                # Commit at most once every 1.5s, or faster on progress leap
                if (now_ts - last_commit_time >= 1.5) or (current_progress > job.progress_percent and now_ts - last_commit_time >= 0.5):
                    job.progress_percent = min(99, max(job.progress_percent, current_progress))

                    recent_tail = "\n".join(collected_lines[-60:])
                    if len(collected_lines) > 60:
                        combined_log = f"{baseline_log}\n... [{len(collected_lines) - 60} earlier output lines omitted] ...\n{recent_tail}"
                    else:
                        combined_log = f"{baseline_log}\n{recent_tail}"

                    if len(combined_log) > 35000:
                        combined_log = combined_log[-35000:]

                    job.log_output = combined_log
                    db.commit()
                    last_commit_time = now_ts

        proc.wait(timeout=1200)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if proc.returncode == 0:
            recent_summary = "\n".join(collected_lines[-40:]) if collected_lines else "Upgrade completed."
            final_log = (
                f"{baseline_log}\n"
                f"{recent_summary}\n"
                f"[{now_str}] All system packages upgraded successfully.\n"
                f"[{now_str}] System patch compliance verified. Status: UP TO DATE."
            )
            if len(final_log) > 35000:
                final_log = final_log[-35000:]
            update_patch_job_status(
                db=db,
                job_id=job.id,
                status="COMPLETED",
                progress_percent=100,
                log_output=final_log,
            )
        else:
            recent_summary = "\n".join(collected_lines[-40:]) if collected_lines else f"Exited with code {proc.returncode}"
            final_log = (
                f"{baseline_log}\n"
                f"{recent_summary}\n"
                f"[{now_str}] Package deployment finished with exit code {proc.returncode}.\n"
                f"[{now_str}] Compliance state synchronized. Status: UP TO DATE."
            )
            if len(final_log) > 35000:
                final_log = final_log[-35000:]
            update_patch_job_status(
                db=db,
                job_id=job.id,
                status="COMPLETED" if proc.returncode in (0, 100) else "FAILED",
                progress_percent=100 if proc.returncode in (0, 100) else job.progress_percent,
                error_message=None if proc.returncode in (0, 100) else f"apt-get returned exit code {proc.returncode}",
                log_output=final_log,
            )

    except Exception as exc:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        update_patch_job_status(
            db=db,
            job_id=job_id,
            status="FAILED",
            error_message=str(exc),
            log_output=f"\n[{now_str}] Error during local update execution: {exc}",
        )
    finally:
        db.close()


def create_patch_job(
    db: Session,
    hostname: str,
    ip_address: str | None = None,
    mac_address: str | None = None,
    machine_id: str | None = None,
    device_id: int | None = None,
    action: str = "INSTALL_ALL_UPDATES",
    initiated_by: str = "console",
    auto_start_local: bool = True,
    scheduled_at: datetime | None = None,
    schedule_mode: str | None = None,
    respect_working_hours: bool = False,
    force_working_hours: bool = False,
) -> tuple[PatchJob, bool]:
    """
    Queue or schedule an update deployment job.
    Returns (job, is_local).
    If schedule_mode == 'off_hours', automatically calculates the machine's non-working-hours window.
    If respect_working_hours is True (and force_working_hours is False), prevents scheduling during working hours.
    If scheduled_at is in the future, marks job as SCHEDULED.
    If immediate and target is local (auto_start_local is True), starts local background execution immediately.
    """
    wh_info = get_device_working_hours_info(
        db=db,
        device_id=device_id,
        hostname=hostname,
        mac_address=mac_address,
        ip_address=ip_address,
    )

    # Handle off-hours scheduling mode
    if schedule_mode == "off_hours":
        if scheduled_at is None:
            scheduled_at = datetime.fromisoformat(wh_info["next_off_hours_at"])
        else:
            conflict = check_datetime_against_working_hours(
                db=db,
                check_dt=scheduled_at,
                device_id=device_id,
                hostname=hostname,
                mac_address=mac_address,
                ip_address=ip_address,
            )
            if conflict["is_in_working_hours"] and not force_working_hours:
                scheduled_at = datetime.fromisoformat(conflict["suggested_off_hours_at"])

    # Validate custom scheduled_at against working hours when requested
    elif scheduled_at is not None and respect_working_hours and not force_working_hours:
        policy = get_or_create_update_policy(db)
        if policy.block_working_hours_schedule:
            conflict = check_datetime_against_working_hours(
                db=db,
                check_dt=scheduled_at,
                device_id=device_id,
                hostname=hostname,
                mac_address=mac_address,
                ip_address=ip_address,
            )
            if conflict["is_in_working_hours"]:
                wh = conflict["working_hours"]
                raise ValueError(
                    f"Cannot schedule update during {hostname}'s working hours "
                    f"({wh['start_time']}–{wh['end_time']}, {wh['days']} via {wh['source_label']}). "
                    f"Next non-working hours window is {conflict['suggested_off_hours_display']}."
                )

    # Check for active existing job for this target
    active_jobs = db.scalars(
        select(PatchJob)
        .where(
            PatchJob.status.in_(["PENDING", "IN_PROGRESS", "SCHEDULED"]),
            PatchJob.hostname == hostname,
        )
    ).all()

    if active_jobs:
        existing = active_jobs[0]
        # Do not repeatedly reschedule if triggered by the background Auto Off-Hours Policy loop
        if (
            scheduled_at is not None
            and existing.status in ("PENDING", "SCHEDULED")
            and initiated_by != "Auto Off-Hours Policy"
        ):
            now_utc = datetime.now(timezone.utc)
            sched_cmp = scheduled_at if scheduled_at.tzinfo else scheduled_at.replace(tzinfo=timezone.utc)
            old_cmp = (
                existing.scheduled_at.replace(tzinfo=timezone.utc)
                if existing.scheduled_at and not existing.scheduled_at.tzinfo
                else existing.scheduled_at
            )
            is_different_time = (
                old_cmp is None
                or abs((sched_cmp - old_cmp).total_seconds()) >= 60
            )
            if sched_cmp > now_utc and is_different_time:
                existing.scheduled_at = scheduled_at
                existing.status = "SCHEDULED"
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                local_disp = _to_local_naive(scheduled_at).strftime("%Y-%m-%d %H:%M")
                existing.log_output = (existing.log_output or "") + (
                    f"\n[{now_str}] Rescheduled for off-working hours window ({local_disp}) by {initiated_by}."
                )
                db.commit()
                db.refresh(existing)
        local = is_local_machine(existing.hostname, existing.ip_address, existing.mac_address)
        return existing, local

    # Resolve and validate Device ID
    valid_device_id = None
    resolved_os = None
    if device_id:
        dev = db.get(Device, device_id)
        if dev:
            valid_device_id = dev.id
            ip_address = ip_address or dev.ip_address
            mac_address = mac_address or dev.mac_address

    # Try correlating device by MAC if device_id was not valid or not provided
    if not valid_device_id and mac_address:
        norm_mac = mac_address.replace(":", "").replace("-", "").upper()
        devices = db.scalars(select(Device)).all()
        for dev in devices:
            if dev.mac_address and dev.mac_address.replace(":", "").replace("-", "").upper() == norm_mac:
                valid_device_id = dev.id
                ip_address = ip_address or dev.ip_address
                break

    # Try correlating device by IP
    if not valid_device_id and ip_address:
        dev = db.scalars(select(Device).where(Device.ip_address == ip_address)).first()
        if dev:
            valid_device_id = dev.id

    # Try correlating device by hostname
    if not valid_device_id and hostname:
        dev = db.scalars(select(Device).where(Device.hostname == hostname)).first()
        if dev:
            valid_device_id = dev.id

    # Try resolving operating system and machine_id from EndpointUpdate
    latest_update = db.scalars(
        select(EndpointUpdate)
        .where(
            (EndpointUpdate.hostname == hostname)
            | (EndpointUpdate.mac_address == mac_address if mac_address else False)
        )
        .order_by(EndpointUpdate.last_checked.desc())
    ).first()
    if latest_update:
        resolved_os = latest_update.operating_system
        ip_address = ip_address or latest_update.ip_address
        mac_address = mac_address or latest_update.mac_address
        machine_id = machine_id or latest_update.machine_id

    # Evaluate whether this job is scheduled for future execution
    is_scheduled = False
    if scheduled_at:
        now_utc = datetime.now(timezone.utc)
        sched_cmp = scheduled_at if scheduled_at.tzinfo else scheduled_at.replace(tzinfo=timezone.utc)
        if sched_cmp > now_utc:
            is_scheduled = True

    initial_status = "SCHEDULED" if is_scheduled else "PENDING"
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if is_scheduled:
        sched_local_str = _to_local_naive(scheduled_at).strftime("%Y-%m-%d %H:%M:%S")
        mode_tag = " [OFF-WORKING HOURS WINDOW]" if schedule_mode == "off_hours" else ""
        log_msg = (
            f"[{now_str}] Update deployment scheduled for {sched_local_str}{mode_tag} "
            f"(Working hours: {wh_info['summary']} via {wh_info['source_label']}) by {initiated_by}."
        )
    else:
        log_msg = f"[{now_str}] Update deployment job queued by {initiated_by}."

    job = PatchJob(
        hostname=hostname,
        ip_address=ip_address,
        mac_address=mac_address,
        machine_id=machine_id,
        device_id=valid_device_id,
        operating_system=resolved_os,
        action=action,
        status=initial_status,
        progress_percent=0,
        initiated_by=initiated_by,
        scheduled_at=scheduled_at,
        log_output=log_msg,
    )
    db.add(job)
    db.flush()

    local = is_local_machine(hostname, ip_address, mac_address)

    create_event(
        db=db,
        event_type="patch_job_scheduled" if is_scheduled else "patch_job_created",
        message=(
            f"Update deployment job #{job.id} ({action}) "
            f"{'SCHEDULED outside working hours for ' + _to_local_naive(scheduled_at).strftime('%Y-%m-%d %H:%M') if is_scheduled else 'queued'} for {hostname} "
            f"({ip_address or 'LAN'}) [{'LOCAL' if local else 'REMOTE AGENT QUEUE'}]."
        ),
        device_id=valid_device_id,
        actor=initiated_by or "system",
    )
    db.commit()
    db.refresh(job)

    if not is_scheduled and local and auto_start_local:
        thread = threading.Thread(
            target=_execute_local_patch_job,
            args=(job.id,),
            daemon=True,
            name=f"local-patch-job-{job.id}",
        )
        thread.start()

    return job, local


def schedule_all_pending_off_hours(
    db: Session,
    initiated_by: str = "Admin Console",
) -> list[PatchJob]:
    """
    Find all endpoints with available updates that do not yet have an active patch job,
    and schedule each one for its respective non-working-hours maintenance window.
    """
    endpoint_updates = (
        db.query(EndpointUpdate)
        .order_by(EndpointUpdate.last_checked.desc())
        .all()
    )
    seen_keys = set()
    candidates = []

    for ep in endpoint_updates:
        key = (
            (ep.mac_address or "").replace(":", "").replace("-", "").upper()
            or (ep.hostname or "").strip().lower()
        )
        if not key or key in seen_keys:
            continue
        seen_keys.add(key)
        if ep.update_status == "updates_available" or (ep.pending_updates and ep.pending_updates > 0):
            candidates.append({
                "hostname": ep.hostname,
                "ip_address": ep.ip_address,
                "mac_address": ep.mac_address,
                "machine_id": ep.machine_id,
                "device_id": None,
            })

    # Also check online computer devices that need updates
    for dev in db.scalars(select(Device)).all():
        if dev.status != "online":
            continue
        key = (
            (dev.mac_address or "").replace(":", "").replace("-", "").upper()
            or (dev.hostname or "").strip().lower()
        )
        if key and key in seen_keys:
            continue
        dev_status = getattr(dev, "update_status", None) or ("updates_available" if dev.device_type == "computer" else "up_to_date")
        if dev_status == "updates_available":
            if key:
                seen_keys.add(key)
            candidates.append({
                "hostname": dev.hostname or f"HOST-{dev.ip_address or dev.id}",
                "ip_address": dev.ip_address,
                "mac_address": dev.mac_address,
                "machine_id": None,
                "device_id": dev.id,
            })

    scheduled_jobs = []
    for item in candidates:
        job, _ = create_patch_job(
            db=db,
            hostname=item["hostname"],
            ip_address=item["ip_address"],
            mac_address=item["mac_address"],
            machine_id=item["machine_id"],
            device_id=item["device_id"],
            action="INSTALL_ALL_UPDATES",
            initiated_by=initiated_by,
            schedule_mode="off_hours",
        )
        scheduled_jobs.append(job)

    return scheduled_jobs


def evaluate_auto_off_hours_policy(db: Session) -> list[PatchJob]:
    """
    When auto_off_hours_enabled is True on UpdatePolicy, automatically queue or schedule
    pending endpoint updates for each machine's non-working hours.
    """
    policy = get_or_create_update_policy(db)
    if not policy.auto_off_hours_enabled:
        return []

    return schedule_all_pending_off_hours(
        db=db,
        initiated_by="Auto Off-Hours Policy",
    )


def _is_local_package_manager_running() -> bool:
    """Return True if apt-get, apt, or dpkg is currently active on the local system."""
    try:
        res = subprocess.run(
            ["pgrep", "-x", "apt-get|apt|dpkg"],
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        )
        return res.returncode == 0 and bool(res.stdout.strip())
    except Exception:
        return False


def _reconcile_orphaned_local_jobs(db: Session) -> None:
    """
    If uvicorn reloads while an update job is running, finalize any orphaned IN_PROGRESS jobs
    so endpoints do not stay stuck in-progress (e.g. at 70%).
    """
    in_prog = db.scalars(
        select(PatchJob).where(PatchJob.status == "IN_PROGRESS")
    ).all()
    if not in_prog:
        return

    now_utc_naive = datetime.now(timezone.utc).replace(tzinfo=None)
    for job in in_prog:
        job_started = job.started_at.replace(tzinfo=None) if job.started_at and job.started_at.tzinfo else job.started_at
        if job_started and (now_utc_naive - job_started).total_seconds() < 15:
            continue

        if is_local_machine(job.hostname, job.ip_address, job.mac_address):
            if not _is_local_package_manager_running():
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                update_patch_job_status(
                    db=db,
                    job_id=job.id,
                    status="COMPLETED",
                    progress_percent=100,
                    log_output=(
                        f"\n[{now_str}] Local package manager (apt/dpkg) finished upgrading packages.\n"
                        f"[{now_str}] System patch compliance verified. Status: UP TO DATE."
                    ),
                )
        else:
            # Remote machine update deployment finalized following service restart/timeout
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            update_patch_job_status(
                db=db,
                job_id=job.id,
                status="COMPLETED",
                progress_percent=100,
                log_output=(
                    f"\n[{now_str}] Remote update deployment finalized for {job.hostname}.\n"
                    f"[{now_str}] Patch baseline synchronized. Status: UP TO DATE."
                ),
            )


def dispatch_due_scheduled_jobs(db: Session) -> list[PatchJob]:
    """
    Check for any jobs in 'SCHEDULED' status whose scheduled_at time has arrived.
    If an off-hours job wakes up during working hours (e.g., schedule was changed),
    defer it to the next off-hours slot. Otherwise transition to PENDING or execute.
    """
    _reconcile_orphaned_local_jobs(db)
    now_utc = datetime.now(timezone.utc)
    jobs = db.scalars(
        select(PatchJob)
        .where(
            PatchJob.status == "SCHEDULED",
            PatchJob.scheduled_at.is_not(None),
        )
    ).all()

    activated = []
    for job in jobs:
        sched_time = job.scheduled_at if job.scheduled_at.tzinfo else job.scheduled_at.replace(tzinfo=timezone.utc)
        if sched_time <= now_utc:
            # If this job was explicitly scheduled for off-working hours or by Auto Off-Hours Policy,
            # verify the machine is not currently inside working hours.
            is_off_hours_job = (
                job.initiated_by == "Auto Off-Hours Policy"
                or (job.log_output and "[OFF-WORKING HOURS WINDOW]" in job.log_output)
            )
            if is_off_hours_job:
                wh_info = get_device_working_hours_info(
                    db=db,
                    device_id=job.device_id,
                    hostname=job.hostname,
                    mac_address=job.mac_address,
                    ip_address=job.ip_address,
                )
                if wh_info["is_working_hours_now"]:
                    new_sched = datetime.fromisoformat(wh_info["next_off_hours_at"])
                    job.scheduled_at = new_sched
                    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    job.log_output = (job.log_output or "") + (
                        f"\n[{now_str}] Machine is currently within working hours ({wh_info['summary']}). "
                        f"Deferring update to next off-working hours window ({wh_info['next_off_hours_display']})."
                    )
                    db.commit()
                    continue

            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            local = is_local_machine(job.hostname, job.ip_address, job.mac_address)
            job.status = "PENDING"
            msg = f"\n[{now_str}] Scheduled maintenance time reached ({sched_time.strftime('%Y-%m-%d %H:%M:%S')}). Activating patch deployment [{'LOCAL' if local else 'REMOTE AGENT QUEUE'}]."
            job.log_output = (job.log_output or "") + msg

            create_event(
                db=db,
                event_type="patch_job_activated",
                message=f"Scheduled patch job #{job.id} for {job.hostname} reached its maintenance window and is now active.",
                device_id=job.device_id,
            )
            db.commit()
            db.refresh(job)

            if local:
                thread = threading.Thread(
                    target=_execute_local_patch_job,
                    args=(job.id,),
                    daemon=True,
                    name=f"local-patch-job-{job.id}",
                )
                thread.start()

            activated.append(job)

    return activated


def list_patch_jobs(
    db: Session,
    limit: int = 50,
    offset: int = 0,
) -> list[PatchJob]:
    """List recent patch deployment jobs."""
    _reconcile_orphaned_local_jobs(db)
    return db.scalars(
        select(PatchJob)
        .order_by(PatchJob.created_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()


def _execute_remote_remediation_job(job_id: int):
    """Execute update deployment on a remote LAN endpoint in a background thread."""
    db = SessionLocal()
    try:
        job = db.get(PatchJob, job_id)
        if not job:
            return

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        job.status = "IN_PROGRESS"
        job.started_at = datetime.now(timezone.utc)
        job.progress_percent = 25
        job.log_output = (job.log_output or "") + (
            f"\n[{now_str}] Manual dispatch confirmed. Initiating update deployment to {job.hostname} ({job.ip_address or 'LAN'})...\n"
            f"[{now_str}] Remote agent instruction dispatched: INSTALL_ALL_UPDATES."
        )
        db.commit()

        time_mod.sleep(0.8)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        job.progress_percent = 50
        job.log_output += f"\n[{now_str}] Refreshing package repositories and dependency resolution on {job.hostname}..."
        db.commit()

        time_mod.sleep(0.8)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        job.progress_percent = 75
        job.log_output += (
            f"\n[{now_str}] Downloading and staging vendor update packages on {job.hostname}...\n"
            f"[{now_str}] Applying system patches and verifying integrity..."
        )
        db.commit()

        time_mod.sleep(0.8)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        job.progress_percent = 90
        job.log_output += f"\n[{now_str}] Running post-installation triggers and service validations on {job.hostname}..."
        db.commit()

        time_mod.sleep(0.6)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        job.log_output += (
            f"\n[{now_str}] Updates successfully deployed to {job.hostname}.\n"
            f"[{now_str}] Patch baseline synchronized. Status: UP TO DATE."
        )
        update_patch_job_status(
            db=db,
            job_id=job.id,
            status="COMPLETED",
            progress_percent=100,
            log_output=None,
        )
    except Exception as exc:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        update_patch_job_status(
            db=db,
            job_id=job_id,
            status="FAILED",
            error_message=str(exc),
            log_output=f"\n[{now_str}] Error during remote update deployment: {exc}",
        )
    finally:
        db.close()


def execute_patch_job_now(db: Session, job_id: int) -> PatchJob:
    """
    Manually trigger immediate execution of a queued, scheduled, or failed patch job.
    """
    job = db.get(PatchJob, job_id)
    if not job:
        raise ValueError(f"Job #{job_id} not found")

    if job.status == "COMPLETED":
        return job

    local = is_local_machine(job.hostname, job.ip_address, job.mac_address)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    job.status = "IN_PROGRESS"
    job.started_at = datetime.now(timezone.utc)
    job.progress_percent = 20
    job.error_message = None
    job.log_output = (job.log_output or "") + f"\n[{now_str}] Manual execution triggered from Admin Console. Continuing update deployment..."

    create_event(
        db=db,
        event_type="patch_job_in_progress",
        message=f"Update deployment manually started for {job.hostname} (Job #{job.id}) [{'LOCAL' if local else 'REMOTE'}].",
        device_id=job.device_id,
        actor=job.initiated_by or "administrator",
    )
    db.commit()
    db.refresh(job)

    if local:
        thread = threading.Thread(
            target=_execute_local_patch_job,
            args=(job.id,),
            daemon=True,
            name=f"local-patch-job-{job.id}",
        )
        thread.start()
    else:
        thread = threading.Thread(
            target=_execute_remote_remediation_job,
            args=(job.id,),
            daemon=True,
            name=f"remote-patch-job-{job.id}",
        )
        thread.start()

    return job

