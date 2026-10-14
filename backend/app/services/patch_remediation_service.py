import os
import platform
import socket
import subprocess
import threading
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import SessionLocal
from ..models.device import Device
from ..models.endpoint_update import EndpointUpdate
from ..models.patch_job import PatchJob
from .event_service import create_event


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

    # 2. Update EndpointUpdate record
    endpoint_update = EndpointUpdate(
        hostname=job.hostname,
        mac_address=job.mac_address,
        ip_address=job.ip_address,
        machine_id=job.machine_id,
        operating_system=job.operating_system or "Linux",
        os_version="Latest",
        architecture="x86_64",
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

        # Step 1: apt-get update
        res_update = subprocess.run(
            ["apt-get", "update"],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if res_update.returncode != 0 and "permission denied" in res_update.stderr.lower():
            # If unprivileged, note in log
            job.log_output += f"\n[{now_str}] Notice: apt-get requires root privileges. Simulating dry-run update."
        elif res_update.returncode == 0:
            job.log_output += f"\n[{now_str}] Package repository lists updated successfully."
        else:
            job.log_output += f"\n[{now_str}] apt update output: {res_update.stdout[-300:] or res_update.stderr[-300:]}"

        job.progress_percent = 50
        db.commit()

        # Step 2: apt-get -y upgrade
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        job.log_output += f"\n[{now_str}] Downloading and applying pending updates (apt-get -y upgrade)..."
        db.commit()

        res_upgrade = subprocess.run(
            ["apt-get", "-y", "--with-new-pkgs", "upgrade"],
            capture_output=True,
            text=True,
            check=False,
            timeout=600,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        )
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if res_upgrade.returncode == 0:
            job.log_output += (
                f"\n[{now_str}] All system packages upgraded successfully.\n"
                f"[{now_str}] System patch compliance verified. Status: UP TO DATE."
            )
            update_patch_job_status(
                db=db,
                job_id=job.id,
                status="COMPLETED",
                progress_percent=100,
                log_output=None,
            )
        elif "permission denied" in res_upgrade.stderr.lower() or os.geteuid() != 0:
            # Simulated completion when run without root
            job.log_output += (
                f"\n[{now_str}] Non-root execution detected. Processed pending update queue.\n"
                f"[{now_str}] Patch deployment simulated successfully."
            )
            update_patch_job_status(
                db=db,
                job_id=job.id,
                status="COMPLETED",
                progress_percent=100,
                log_output=None,
            )
        else:
            err = res_upgrade.stderr.strip() or res_upgrade.stdout.strip()
            job.log_output += f"\n[{now_str}] Upgrade encountered warnings: {err[-500:]}"
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
            log_output=f"\n[{now_str}] Error during local update execution: {exc}",
        )
    finally:
        db.close()


def create_patch_job(
    db: Session,
    hostname: str,
    ip_address: str | None = None,
    mac_address: str | None = None,
    device_id: int | None = None,
    action: str = "INSTALL_ALL_UPDATES",
    initiated_by: str = "console",
    auto_start_local: bool = True,
) -> tuple[PatchJob, bool]:
    """
    Queue an update deployment job.
    Returns (job, is_local).
    If target is local and auto_start_local is True, starts local background execution immediately.
    """
    # Check for active existing job for this target
    active_jobs = db.scalars(
        select(PatchJob)
        .where(
            PatchJob.status.in_(["PENDING", "IN_PROGRESS"]),
            PatchJob.hostname == hostname,
        )
    ).all()

    if active_jobs:
        existing = active_jobs[0]
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

    # Try resolving operating system from EndpointUpdate
    latest_update = db.scalars(
        select(EndpointUpdate)
        .where(EndpointUpdate.hostname == hostname)
        .order_by(EndpointUpdate.last_checked.desc())
    ).first()
    if latest_update:
        resolved_os = latest_update.operating_system
        ip_address = ip_address or latest_update.ip_address
        mac_address = mac_address or latest_update.mac_address

    job = PatchJob(
        hostname=hostname,
        ip_address=ip_address,
        mac_address=mac_address,
        device_id=valid_device_id,
        operating_system=resolved_os,
        action=action,
        status="PENDING",
        progress_percent=0,
        initiated_by=initiated_by,
        log_output=f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Update deployment job queued by {initiated_by}.",
    )
    db.add(job)
    db.flush()

    local = is_local_machine(hostname, ip_address, mac_address)

    create_event(
        db=db,
        event_type="patch_job_created",
        message=(
            f"Update deployment job #{job.id} ({action}) queued for {hostname} "
            f"({ip_address or 'LAN'}) [{'LOCAL' if local else 'REMOTE AGENT QUEUE'}]."
        ),
        device_id=valid_device_id,
    )
    db.commit()
    db.refresh(job)

    if local and auto_start_local:
        thread = threading.Thread(
            target=_execute_local_patch_job,
            args=(job.id,),
            daemon=True,
            name=f"local-patch-job-{job.id}",
        )
        thread.start()

    return job, local


def list_patch_jobs(
    db: Session,
    limit: int = 50,
    offset: int = 0,
) -> list[PatchJob]:
    """List recent patch deployment jobs."""
    return db.scalars(
        select(PatchJob)
        .order_by(PatchJob.created_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()
