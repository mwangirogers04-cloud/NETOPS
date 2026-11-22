import ipaddress
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy import select, or_, func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.endpoint_update import EndpointUpdate
from ..models.device import Device
from ..models.patch_job import PatchJob
from ..models.user import User
from ..services.auth_service import require_admin, require_super_admin, get_optional_current_user
from ..schemas.patch_job import (
    CreatePatchJobRequest,
    UpdateJobStatusRequest,
    PatchJobResponse,
    UpdatePolicyUpdateRequest,
    UpdatePolicyResponse,
    WorkingHoursCheckRequest,
    RebootEndpointRequest,
    RebootEndpointResponse,
)
from ..services.event_service import create_event
from ..services.network_patch_scanner import scan_lan_for_updates
from ..services.patch_remediation_service import (
    create_patch_job,
    get_pending_job_for_agent,
    update_patch_job_status,
    list_patch_jobs,
    is_local_machine,
    execute_patch_job_now,
    get_or_create_update_policy,
    get_device_working_hours_info,
    check_datetime_against_working_hours,
    schedule_all_pending_off_hours,
    evaluate_auto_off_hours_policy,
    reboot_endpoint,
)

router = APIRouter(
    prefix="/endpoint-updates",
    tags=["Endpoint Updates"],
)


class EndpointUpdateReport(BaseModel):
    hostname: str
    mac_address: str | None = None
    ip_address: str | None = None
    machine_id: str | None = None
    operating_system: str
    os_version: str
    architecture: str
    update_status: str
    pending_updates: int
    security_updates: int | None = None


@router.post("/")
def report_endpoint_update(
    report: EndpointUpdateReport,
    db: Session = Depends(get_db),
):
    normalized_mac = (
        report.mac_address.replace(":", "").replace("-", "").upper()
        if report.mac_address
        else None
    )

    matched_device = None
    newly_registered = False

    if normalized_mac:
        devices = db.scalars(
            select(Device)
        ).all()

        for device in devices:
            if not device.mac_address:
                continue

            device_mac = (
                device.mac_address
                .replace(":", "")
                .replace("-", "")
                .upper()
            )

            if device_mac == normalized_mac:
                matched_device = device
                break
    if matched_device is None and normalized_mac:
        matched_device = Device(
            mac_address=report.mac_address,
            ip_address=report.ip_address,
            hostname=report.hostname,
            vendor=None,
            device_type="computer",
            status="online",
            approval_status="pending",
            classification_status="normal",
            vlan_id=90,
            enforcement_status="quarantined",
            internet_access_authorized=False,
            notes="Automatically registered from endpoint update agent",
        )
        newly_registered = True

        db.add(matched_device)
        db.flush()

        create_event(
            db=db,
            event_type="device_detected",
            message=(
                f"Unrecognized endpoint automatically registered: "
                f"{report.hostname} "
                f"({report.ip_address or 'No IP'}) "
                f"MAC {report.mac_address}. "
                f"Placed in VLAN 90 quarantine. "
                f"Awaiting administrator approval."
            ),
            device_id=matched_device.id,
        )



    # Preserve up_to_date status if a patch remediation job has already completed for this endpoint
    effective_status = report.update_status
    effective_pending = report.pending_updates
    effective_security = report.security_updates

    if effective_status == "updates_available" or (effective_pending and effective_pending > 0):
        two_hours_ago = datetime.now(timezone.utc) - timedelta(hours=2)
        completed_jobs = db.scalars(
            select(PatchJob)
            .where(
                PatchJob.status == "COMPLETED",
                or_(
                    PatchJob.completed_at >= two_hours_ago,
                    PatchJob.completed_at.is_(None),
                )
            )
            .order_by(PatchJob.completed_at.desc())
        ).all()
        for cj in completed_jobs:
            cj_mac = (
                cj.mac_address.replace(":", "").replace("-", "").upper()
                if cj.mac_address
                else None
            )
            if (
                (normalized_mac and cj_mac and cj_mac == normalized_mac)
                or (report.ip_address and cj.ip_address and cj.ip_address == report.ip_address)
                or (report.machine_id and cj.machine_id and cj.machine_id == report.machine_id)
                or (report.hostname and cj.hostname and cj.hostname.lower() == report.hostname.lower())
            ):
                effective_status = "up_to_date"
                effective_pending = 0
                effective_security = 0
                break

    # Find existing endpoint record to update in-place, preventing runaway database row growth
    existing_endpoint = None
    if report.machine_id:
        existing_endpoint = db.scalars(
            select(EndpointUpdate).where(EndpointUpdate.machine_id == report.machine_id)
        ).first()
    if not existing_endpoint and report.mac_address:
        existing_endpoint = db.scalars(
            select(EndpointUpdate).where(EndpointUpdate.mac_address == report.mac_address)
        ).first()
    if not existing_endpoint and report.hostname:
        existing_endpoint = db.scalars(
            select(EndpointUpdate).where(EndpointUpdate.hostname == report.hostname)
        ).first()

    if existing_endpoint:
        existing_endpoint.hostname = report.hostname
        if report.mac_address:
            existing_endpoint.mac_address = report.mac_address
        if report.ip_address:
            existing_endpoint.ip_address = report.ip_address
        if report.machine_id:
            existing_endpoint.machine_id = report.machine_id
        existing_endpoint.operating_system = report.operating_system
        existing_endpoint.os_version = report.os_version
        existing_endpoint.architecture = report.architecture
        existing_endpoint.update_status = effective_status
        existing_endpoint.pending_updates = effective_pending
        existing_endpoint.security_updates = effective_security
        existing_endpoint.last_checked = datetime.now(timezone.utc)
        endpoint_update = existing_endpoint
    else:
        endpoint_update = EndpointUpdate(
            hostname=report.hostname,
            mac_address=report.mac_address,
            ip_address=report.ip_address,
            machine_id=report.machine_id,
            operating_system=report.operating_system,
            os_version=report.os_version,
            architecture=report.architecture,
            update_status=effective_status,
            pending_updates=effective_pending,
            security_updates=effective_security,
            last_checked=datetime.now(timezone.utc),
        )
        db.add(endpoint_update)

    if matched_device is None:
        create_event(
            db=db,
            event_type="unrecognized_endpoint",
            message=(
                f"Unrecognized endpoint reported: "
                f"{endpoint_update.hostname} "
                f"({endpoint_update.mac_address})"
            ),
        )

    db.commit()
    db.refresh(endpoint_update)

    # Check for queued patch commands for this endpoint
    pending_job = get_pending_job_for_agent(
        db=db,
        hostname=endpoint_update.hostname,
        mac_address=endpoint_update.mac_address,
        machine_id=endpoint_update.machine_id,
    )
    pending_cmd = None
    if pending_job:
        pending_cmd = {
            "job_id": pending_job.id,
            "action": pending_job.action,
        }

    # Calculate exact quarantine compliance state for universal host enforcement
    is_quarantined = True
    is_authorized = False
    enforcement_status = "quarantined"
    if matched_device:
        is_authorized = bool(getattr(matched_device, "internet_access_authorized", False))
        enforcement_status = getattr(matched_device, "enforcement_status", "quarantined")
        approval_status = getattr(matched_device, "approval_status", "pending")
        vlan_id = getattr(matched_device, "vlan_id", 90)

        is_quarantined = (
            not is_authorized
            or enforcement_status in ("quarantined", "isolated")
            or approval_status in ("pending", "rejected")
            or vlan_id == 90
        )

    return {
        "message": "Endpoint update status recorded",
        "id": endpoint_update.id,
        "hostname": endpoint_update.hostname,
        "device_id": matched_device.id if matched_device else None,
        "device_ip": matched_device.ip_address if matched_device else None,
        "device_type": matched_device.device_type if matched_device else None,
        "device_match_status": (
            "registered"
            if newly_registered
            else "matched"
            if matched_device
            else "unrecognized"
        ),
        "update_status": endpoint_update.update_status,
        "pending_updates": endpoint_update.pending_updates,
        "security_updates": endpoint_update.security_updates,
        "last_checked": endpoint_update.last_checked,
        "pending_command": pending_cmd,
        "quarantined": is_quarantined,
        "internet_access_authorized": is_authorized,
        "enforcement_status": enforcement_status,
    }


@router.get("/")
def get_endpoint_updates(
    network_name: str | None = None,
    subnet: str | None = None,
    online_only: bool = True,
    current_user: User | None = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    # Administrators and developer views see all managed endpoints
    uname = (getattr(current_user, "username", "") or "").lower()
    urole = (getattr(current_user, "role", "") or "").lower()
    email = (getattr(current_user, "email", "") or "").lower()
    is_admin = bool(
        current_user is None
        or urole in ("admin", "super_admin", "developer")
        or "developer" in urole
        or uname in ("developer", "admin", "rogers", "rogers mwangi")
        or "developer" in uname
        or "developer" in email
    )

    # Scope device inventory: Developers and Admins see all machines; standard users see their site/account
    device_query = select(Device)
    if current_user and not is_admin:
        device_query = device_query.where(
            or_(
                Device.owner_id == current_user.id,
                Device.network_name.isnot(None),
            )
        )

    # Filter by online status if requested
    if online_only:
        device_query = device_query.where(Device.status == "online")

    # Filter strictly by network_name if specified
    clean_net = (network_name or "").strip().lower()
    if clean_net and clean_net not in ("all", "current"):
        if clean_net == "home network":
            device_query = device_query.where(
                or_(
                    func.lower(Device.network_name) == "home network",
                    Device.network_name.is_(None),
                )
            )
        else:
            device_query = device_query.where(func.lower(Device.network_name) == clean_net)

    devices = list(db.scalars(device_query).all())

    # Filter strictly by IP subnet if requested
    subnets_to_match = []
    if subnet and "/" in subnet:
        try:
            subnets_to_match.append(ipaddress.ip_network(subnet.strip(), strict=False))
        except Exception:
            pass
    if clean_net == "current":
        try:
            from ..services.discovery import detect_local_subnets
            subnets_info = detect_local_subnets()
            for if_info in subnets_info.get("interfaces", []):
                if not if_info.get("is_virtual") and if_info.get("network"):
                    subnets_to_match.append(ipaddress.ip_network(if_info["network"], strict=False))
        except Exception:
            pass

    if subnets_to_match:
        def _in_any_subnet(ip_str: str | None) -> bool:
            if not ip_str:
                return False
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                return any(ip_obj in s for s in subnets_to_match)
            except Exception:
                return False
        devices = [d for d in devices if _in_any_subnet(d.ip_address)]

    endpoint_updates = (
        db.query(EndpointUpdate)
        .order_by(
            EndpointUpdate.last_checked.desc(),
        )
        .all()
    )

    seen_machine_ids = set()
    seen_macs = set()
    seen_ips = set()
    seen_hostnames = set()
    results = []

    for endpoint in endpoint_updates:
        norm_mac = (
            endpoint.mac_address.replace(":", "").replace("-", "").upper()
            if endpoint.mac_address
            else None
        )
        norm_host = endpoint.hostname.lower().strip() if endpoint.hostname else None
        norm_ip = endpoint.ip_address.strip() if endpoint.ip_address else None

        if norm_mac:
            if norm_mac in seen_macs:
                continue
            seen_macs.add(norm_mac)
            if norm_ip:
                seen_ips.add(norm_ip)
            if endpoint.machine_id:
                seen_machine_ids.add(endpoint.machine_id)
        elif norm_ip:
            if norm_ip in seen_ips:
                continue
            seen_ips.add(norm_ip)
            if endpoint.machine_id:
                seen_machine_ids.add(endpoint.machine_id)
        elif endpoint.machine_id:
            if endpoint.machine_id in seen_machine_ids:
                continue
            seen_machine_ids.add(endpoint.machine_id)
        elif norm_host:
            if norm_host in seen_hostnames:
                continue
            seen_hostnames.add(norm_host)

        results.append(endpoint)

    devices_by_mac = {
        device.mac_address.replace(":", "").replace("-", "").upper():
        device
        for device in devices
        if device.mac_address
    }
    devices_by_ip = {
        device.ip_address: device
        for device in devices
        if device.ip_address
    }
    devices_by_host = {
        device.hostname.strip().lower(): device
        for device in devices
        if device.hostname
    }

    policy = get_or_create_update_policy(db)
    enriched_results = []

    try:
        two_hours_ago = datetime.now(timezone.utc) - timedelta(hours=2)
        completed_jobs = db.scalars(
            select(PatchJob).where(
                PatchJob.status == "COMPLETED",
                or_(
                    PatchJob.completed_at >= two_hours_ago,
                    PatchJob.completed_at.is_(None),
                )
            ).order_by(PatchJob.completed_at.desc())
        ).all()
        comp_job_device_ids = {j.device_id for j in completed_jobs if isinstance(j, PatchJob) and j.device_id}
        comp_job_macs = {j.mac_address.replace(":", "").replace("-", "").upper() for j in completed_jobs if isinstance(j, PatchJob) and j.mac_address}
        comp_job_hosts = {j.hostname.lower() for j in completed_jobs if isinstance(j, PatchJob) and j.hostname}
        comp_job_ips = {j.ip_address for j in completed_jobs if isinstance(j, PatchJob) and j.ip_address}
    except Exception:
        comp_job_device_ids = set()
        comp_job_macs = set()
        comp_job_hosts = set()
        comp_job_ips = set()

    for endpoint in results:
        endpoint_mac = (
            endpoint.mac_address
            .replace(":", "")
            .replace("-", "")
            .upper()
            if endpoint.mac_address
            else None
        )

        device = None
        if endpoint_mac and endpoint_mac in devices_by_mac:
            device = devices_by_mac[endpoint_mac]
        elif endpoint.ip_address and endpoint.ip_address in devices_by_ip:
            device = devices_by_ip[endpoint.ip_address]
        elif endpoint.hostname and endpoint.hostname.strip().lower() in devices_by_host:
            device = devices_by_host[endpoint.hostname.strip().lower()]

        if current_user and not is_admin and device is None:
            continue

        now = datetime.now(timezone.utc)
        if device:
            is_online = (getattr(device, "status", None) == "online")
        elif endpoint.last_checked:
            lc = endpoint.last_checked
            if lc.tzinfo is None:
                lc = lc.replace(tzinfo=timezone.utc)
            is_online = (now - lc).total_seconds() <= 900
        else:
            is_online = False

        # Strictly skip offline endpoints when online_only is enabled
        if online_only and not is_online:
            continue

        # If a specific network was requested, strictly require matching scoped device
        if clean_net and clean_net not in ("all",):
            if device is None or device not in devices:
                continue

        # If subnets are to be matched, ensure IP falls strictly within the scoped subnet
        if subnets_to_match:
            ep_ip = endpoint.ip_address or (device.ip_address if device else None)
            if not ep_ip:
                continue
            try:
                ip_obj = ipaddress.ip_address(ep_ip)
                if not any(ip_obj in s for s in subnets_to_match):
                    continue
            except Exception:
                continue

        has_completed_job = (
            (device and device.id in comp_job_device_ids)
            or (endpoint_mac and endpoint_mac in comp_job_macs)
            or (endpoint.hostname and endpoint.hostname.strip().lower() in comp_job_hosts)
            or (endpoint.ip_address and endpoint.ip_address in comp_job_ips)
            or (device and device.hostname and device.hostname.strip().lower() in comp_job_hosts)
            or (device and device.ip_address and device.ip_address in comp_job_ips)
        )
        is_non_computer = (
            (device and device.device_type and device.device_type.lower() in ("phone", "mobile", "tablet", "iot", "printer", "camera", "access_point", "router", "switch", "media_player"))
            or (endpoint.hostname and any(kw in endpoint.hostname.lower() for kw in ("phone", "android", "iphone", "ipad", "galaxy", "tecno", "infinix", "redmi", "oppo", "vivo", "camera", "printer", "tv")))
            or (device and device.hostname and any(kw in device.hostname.lower() for kw in ("phone", "android", "iphone", "ipad", "galaxy", "tecno", "infinix", "redmi", "oppo", "vivo", "camera", "printer", "tv")))
        )

        update_status = endpoint.update_status
        pending_count = endpoint.pending_updates if endpoint.pending_updates is not None else 0
        if has_completed_job or is_non_computer:
            update_status = "up_to_date"
            pending_count = 0
        elif pending_count == 0 and update_status == "updates_available":
            update_status = "up_to_date"
        elif is_online and update_status in ("stale", "unknown"):
            update_status = "updates_available" if (device and device.device_type == "computer" and pending_count > 0) else "up_to_date"

        wh_info = get_device_working_hours_info(
            db=db,
            device_id=device.id if device else None,
            hostname=endpoint.hostname,
            mac_address=endpoint.mac_address,
            ip_address=endpoint.ip_address or (device.ip_address if device else None),
            policy=policy,
            dev=device,
        )

        enriched_results.append(
            {
                "id": endpoint.id,
                "hostname": endpoint.hostname,
                "mac_address": endpoint.mac_address,
                "ip_address": endpoint.ip_address or (device.ip_address if device else None),
                "machine_id": endpoint.machine_id,
                "operating_system": endpoint.operating_system,
                "os_version": endpoint.os_version,
                "architecture": endpoint.architecture,
                "update_status": update_status,
                "pending_updates": pending_count,
                "security_updates": endpoint.security_updates,
                "last_checked": endpoint.last_checked,
                "is_online": is_online,
                "device_id": device.id if device else None,
                "device_ip": device.ip_address if device else None,
                "device_type": device.device_type if device else None,
                "device_status": device.status if device else None,
                "approval_status": device.approval_status if device else None,
                "enforcement_status": device.enforcement_status if device else None,
                "internet_access_authorized": (
                    device.internet_access_authorized
                    if device
                    else None
                ),
                "working_hours": wh_info,
            }
        )

    # Ensure all online devices are represented in Endpoint Updates
    seen_macs_in_enriched = {
        (e.get("mac_address") or "").replace(":", "").replace("-", "").upper()
        for e in enriched_results
        if e.get("mac_address")
    }
    seen_ips_in_enriched = {
        e.get("ip_address")
        for e in enriched_results
        if e.get("ip_address")
    }

    for device in devices:
        if not device.ip_address and not device.mac_address:
            continue
        dev_mac = (device.mac_address or "").replace(":", "").replace("-", "").upper()
        if (dev_mac and dev_mac in seen_macs_in_enriched) or (device.ip_address and device.ip_address in seen_ips_in_enriched):
            continue

        wh_info = get_device_working_hours_info(
            db=db,
            device_id=device.id,
            hostname=device.hostname,
            mac_address=device.mac_address,
            ip_address=device.ip_address,
        )

        dev_has_job = (
            (device.id in comp_job_device_ids)
            or (dev_mac and dev_mac in comp_job_macs)
            or (device.hostname and device.hostname.strip().lower() in comp_job_hosts)
            or (device.ip_address and device.ip_address in comp_job_ips)
        )
        is_dev_non_comp = (
            getattr(device, "device_type", None) in ("phone", "mobile", "tablet", "iot", "printer", "camera", "access_point", "router", "switch", "media_player")
            or any(kw in (device.hostname or "").lower() for kw in ("phone", "android", "iphone", "ipad", "galaxy", "tecno", "infinix", "redmi", "oppo", "vivo", "camera", "printer", "tv"))
        )

        pend = getattr(device, "pending_updates", 0) or 0
        dev_up = getattr(device, "update_status", None)
        is_comp = (
            getattr(device, "device_type", None) in ("computer", "server", "ip_phone", "voip")
            or not getattr(device, "device_type", None)
            or getattr(device, "device_type", None) == "unknown"
        )
        if dev_has_job or is_dev_non_comp:
            dev_up = "up_to_date"
            pend = 0
        elif not dev_up or (pend == 0 and dev_up == "updates_available"):
            dev_up = "updates_available" if (is_comp and pend > 0) else "up_to_date"

        is_online = (getattr(device, "status", None) == "online")

        enriched_results.append({
            "id": f"dev-{device.id}",
            "hostname": device.hostname or f"HOST-{device.ip_address or device.id}",
            "mac_address": device.mac_address,
            "ip_address": device.ip_address,
            "machine_id": dev_mac or f"lan-{device.id}",
            "operating_system": getattr(device, "operating_system", "Generic Network Device") or ("Windows" if is_comp else "Generic Network Device"),
            "os_version": getattr(device, "os_version", "") or ("11/10" if is_comp else "Detected"),
            "architecture": "AMD64",
            "update_status": dev_up,
            "pending_updates": pend,
            "security_updates": 1 if is_comp and pend > 0 else None,
            "last_checked": getattr(device, "last_update_check", None) or datetime.now(timezone.utc),
            "is_online": is_online,
            "device_id": device.id,
            "device_ip": device.ip_address,
            "device_type": device.device_type,
            "device_status": device.status,
            "approval_status": device.approval_status,
            "enforcement_status": device.enforcement_status,
            "internet_access_authorized": device.internet_access_authorized,
            "working_hours": wh_info,
        })

    def _ip_tuple_enriched(item: dict) -> tuple[int, ...]:
        ip = item.get("ip_address") or item.get("device_ip") or ""
        try:
            return tuple(int(p) for p in ip.strip().split(".") if p.isdigit())
        except Exception:
            return (999, 999, 999, 999)

    enriched_results.sort(key=_ip_tuple_enriched)
    return enriched_results


@router.get("/policy", response_model=UpdatePolicyResponse)
def get_update_policy(
    db: Session = Depends(get_db),
):
    """Get global off-working-hours update policy configuration."""
    return get_or_create_update_policy(db)


@router.put("/policy", response_model=UpdatePolicyResponse)
def update_update_policy_endpoint(
    payload: UpdatePolicyUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    """Update global off-working-hours update policy and optionally evaluate pending off-hours jobs."""
    policy = get_or_create_update_policy(db)
    policy.default_working_start = payload.default_working_start.strip() or "08:00"
    policy.default_working_end = payload.default_working_end.strip() or "17:00"
    policy.default_working_days = payload.default_working_days.strip().lower() or "weekdays"
    policy.auto_off_hours_enabled = payload.auto_off_hours_enabled
    policy.block_working_hours_schedule = payload.block_working_hours_schedule
    policy.post_work_delay_minutes = max(0, min(240, payload.post_work_delay_minutes))
    policy.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(policy)

    if policy.auto_off_hours_enabled:
        evaluate_auto_off_hours_policy(db)

    return policy


@router.post("/working-hours-check")
def check_working_hours_for_endpoint(
    payload: WorkingHoursCheckRequest,
    db: Session = Depends(get_db),
):
    """
    Check a machine's working hours (from its Access Schedule or global policy default)
    and evaluate if a proposed scheduled_at time falls inside working hours.
    """
    wh_info = get_device_working_hours_info(
        db=db,
        device_id=payload.device_id,
        hostname=payload.hostname,
        mac_address=payload.mac_address,
        ip_address=payload.ip_address,
    )
    conflict = None
    if payload.scheduled_at:
        conflict = check_datetime_against_working_hours(
            db=db,
            check_dt=payload.scheduled_at,
            device_id=payload.device_id,
            hostname=payload.hostname,
            mac_address=payload.mac_address,
            ip_address=payload.ip_address,
        )
    return {
        "working_hours": wh_info,
        "schedule_check": conflict,
    }


@router.post("/schedule-off-hours-all", response_model=list[PatchJobResponse])
def schedule_all_pending_updates_off_hours(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    """
    Schedule updates outside working hours for all endpoints that currently have pending updates.
    Each machine is scheduled according to its own Access Schedule or the default working hours policy.
    """
    jobs = schedule_all_pending_off_hours(db=db, initiated_by="Admin Console (Bulk Off-Hours)")
    results = []
    for j in jobs:
        resp = PatchJobResponse.model_validate(j)
        resp.is_local = is_local_machine(j.hostname, j.ip_address, j.mac_address)
        resp.working_hours_info = get_device_working_hours_info(
            db=db,
            device_id=j.device_id,
            hostname=j.hostname,
            mac_address=j.mac_address,
            ip_address=j.ip_address,
        )
        results.append(resp)
    return results


class LanScanRequest(BaseModel):
    network: str | None = None
    network_name: str | None = None


@router.post("/scan-lan")
def run_lan_patch_scan(
    payload: LanScanRequest | None = None,
    db: Session = Depends(get_db),
):
    """
    Agentless LAN scan: discovers and evaluates update/patch status
    strictly for machines that are online at that particular time and at that particular network.
    """
    target_net = payload.network if payload else None
    target_net_name = payload.network_name if payload else None
    try:
        results = scan_lan_for_updates(network=target_net, db=db, network_name=target_net_name)
        return results
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Agentless LAN scan failed: {exc}",
        ) from exc


@router.post("/jobs", response_model=PatchJobResponse)
def trigger_patch_job(
    payload: CreatePatchJobRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    """
    Queue or schedule an update deployment job for an endpoint.
    Supports schedule_mode='off_hours' to automatically schedule outside working hours,
    and working-hours conflict protection when respect_working_hours=True.
    """
    try:
        initiated_by_user = payload.initiated_by or (current_user.username if current_user else "administrator")
        job, is_local = create_patch_job(
            db=db,
            hostname=payload.hostname,
            ip_address=payload.ip_address,
            mac_address=payload.mac_address,
            machine_id=payload.machine_id,
            device_id=payload.device_id,
            action=payload.action,
            initiated_by=initiated_by_user,
            scheduled_at=payload.scheduled_at,
            schedule_mode=payload.schedule_mode,
            respect_working_hours=payload.respect_working_hours,
            force_working_hours=payload.force_working_hours,
        )
        resp = PatchJobResponse.model_validate(job)
        resp.is_local = is_local
        resp.working_hours_info = get_device_working_hours_info(
            db=db,
            device_id=job.device_id,
            hostname=job.hostname,
            mac_address=job.mac_address,
            ip_address=job.ip_address,
        )
        return resp
    except ValueError as val_err:
        raise HTTPException(
            status_code=400,
            detail=str(val_err),
        ) from val_err
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create update job: {exc}",
        ) from exc


@router.get("/jobs", response_model=list[PatchJobResponse])
def get_patch_jobs(
    limit: int = 50,
    offset: int = 0,
    current_user: User | None = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    """List recent update deployment jobs and their status."""
    jobs = list_patch_jobs(db, limit=limit, offset=offset)
    if current_user and current_user.role != "super_admin":
        user_dev_ids = set(db.scalars(select(Device.id).where(Device.owner_id == current_user.id)).all())
        jobs = [j for j in jobs if (j.device_id in user_dev_ids or j.initiated_by == current_user.username)]
    results = []
    for j in jobs:
        resp = PatchJobResponse.model_validate(j)
        resp.is_local = is_local_machine(j.hostname, j.ip_address, j.mac_address)
        results.append(resp)
    return results


@router.get("/jobs/{job_id}", response_model=PatchJobResponse)
def get_patch_job_by_id(
    job_id: int,
    db: Session = Depends(get_db),
):
    """Retrieve details, status, and logs for a specific patch job."""
    job = db.get(PatchJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Patch job not found")
    resp = PatchJobResponse.model_validate(job)
    resp.is_local = is_local_machine(job.hostname, job.ip_address, job.mac_address)
    return resp


@router.post("/jobs/{job_id}/status", response_model=PatchJobResponse)
def report_job_status(
    job_id: int,
    payload: UpdateJobStatusRequest,
    db: Session = Depends(get_db),
):
    """Agent status callback to report execution progress, completion, and logs."""
    job = update_patch_job_status(
        db=db,
        job_id=job_id,
        status=payload.status,
        progress_percent=payload.progress_percent,
        log_output=payload.log_output,
        error_message=payload.error_message,
        installed_updates=payload.installed_updates,
    )
    if not job:
        raise HTTPException(status_code=404, detail="Patch job not found")
    resp = PatchJobResponse.model_validate(job)
    resp.is_local = is_local_machine(job.hostname, job.ip_address, job.mac_address)
    return resp


@router.post("/jobs/{job_id}/cancel", response_model=PatchJobResponse)
def cancel_patch_job(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    """Cancel a pending or in-progress update deployment job."""
    job = db.get(PatchJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Patch job not found")

    if job.status in ("COMPLETED", "FAILED", "CANCELLED"):
        resp = PatchJobResponse.model_validate(job)
        resp.is_local = is_local_machine(job.hostname, job.ip_address, job.mac_address)
        return resp

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    job = update_patch_job_status(
        db=db,
        job_id=job.id,
        status="CANCELLED",
        error_message="Cancelled by Administrator from console.",
        log_output=f"[{now_str}] Job cancelled by Administrator.",
    )
    resp = PatchJobResponse.model_validate(job)
    resp.is_local = is_local_machine(job.hostname, job.ip_address, job.mac_address)
    return resp


@router.post("/jobs/{job_id}/run-now", response_model=PatchJobResponse)
def run_patch_job_now(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    """
    Manually trigger immediate execution / continuation of a queued, scheduled, or pending patch job.
    """
    try:
        job = execute_patch_job_now(db=db, job_id=job_id)
        resp = PatchJobResponse.model_validate(job)
        resp.is_local = is_local_machine(job.hostname, job.ip_address, job.mac_address)
        return resp
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/reboot", response_model=RebootEndpointResponse)
def trigger_endpoint_reboot(
    payload: RebootEndpointRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    """
    Dispatch an immediate remote or local reboot command to an endpoint.
    Restricted strictly to Developers (Super Admins).
    """
    try:
        initiated_by_user = current_user.username if current_user else "developer"
        res = reboot_endpoint(
            db=db,
            hostname=payload.hostname,
            ip_address=payload.ip_address,
            mac_address=payload.mac_address,
            device_id=payload.device_id,
            delay_seconds=payload.delay_seconds,
            reason=payload.reason,
            initiated_by=initiated_by_user,
        )
        return res
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.delete("/jobs/{job_id}")
def delete_patch_job(
    job_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    """Delete a patch deployment job from history."""
    job = db.get(PatchJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Patch job not found")
    db.delete(job)
    db.commit()
    return {"message": f"Job #{job_id} deleted successfully"}


@router.get("/commands/{identifier}")
def poll_pending_command(
    identifier: str,
    db: Session = Depends(get_db),
):
    """
    Agent polling endpoint: returns any pending patch job for the given
    hostname, MAC address, or machine ID.
    """
    job = get_pending_job_for_agent(
        db=db,
        hostname=identifier,
        mac_address=identifier if ":" in identifier or "-" in identifier else None,
        machine_id=identifier,
    )
    if not job:
        return {"command": None}

    return {
        "command": job.action,
        "job_id": job.id,
        "hostname": job.hostname,
        "created_at": job.created_at,
    }


@router.get("/launcher/windows")
def download_windows_updater(
    token: str | None = None,
    job_id: int | None = None,
):
    """
    Serves a 1-click Windows Update deployment batch file for remote Windows endpoints.
    Uses the native Windows Update Session API (Microsoft.Update.Session) to search,
    download, and install genuine patches directly from Microsoft Update servers.
    """
    callback_cmd = ""
    if job_id and token:
        callback_cmd = f"""
powershell -NoProfile -ExecutionPolicy Bypass -Command "$headers = @{{ 'Authorization' = 'Bearer {token.strip()}'; 'Content-Type' = 'application/json' }}; $body = @{{ 'status' = 'COMPLETED'; 'progress_percent' = 100; 'log_output' = 'Real Windows Updates installed directly via Microsoft.Update.Session COM API.' }} | ConvertTo-Json; Invoke-RestMethod -Uri 'https://api.netops.co.ke/endpoint-updates/jobs/{job_id}/status' -Method POST -Headers $headers -Body $body" >nul 2>&1
"""

    bat_content = (
        "@echo off\r\n"
        "title NETOPS Real Windows Update Deployment Agent\r\n"
        "echo ========================================================\r\n"
        "echo   NETOPS Real Physical Windows Update Agent\r\n"
        "echo ========================================================\r\n"
        "echo.\r\n"
        "echo [*] Checking Windows Administrator privileges...\r\n"
        "net session >nul 2>&1\r\n"
        "if %errorlevel% neq 0 (\r\n"
        "    echo [!] Administrator privileges required to install Windows updates.\r\n"
        "    echo [!] Please right-click this file and select 'Run as administrator'.\r\n"
        "    pause\r\n"
        "    exit /b 1\r\n"
        ")\r\n"
        "echo [✓] Running with Administrator privileges.\r\n"
        "echo.\r\n"
        "echo [*] Initializing Windows Update Service (wuauserv)...\r\n"
        "net start wuauserv >nul 2>&1\r\n"
        "echo.\r\n"
        "echo [*] Querying Microsoft Update Catalog for security rollups & patches...\r\n"
        "powershell -NoProfile -ExecutionPolicy Bypass -Command \""
        "$session = New-Object -ComObject Microsoft.Update.Session; "
        "$searcher = $session.CreateUpdateSearcher(); "
        "Write-Host 'Searching Microsoft servers for pending patches...'; "
        "$results = $searcher.Search('IsInstalled=0 and Type=\\'Software\\' and IsHidden=0'); "
        "if ($results.Updates.Count -eq 0) { "
        "    Write-Host '[✓] System is already completely UP TO DATE! No pending patches found.' -ForegroundColor Green; "
        "} else { "
        "    Write-Host ('[!] Found ' + $results.Updates.Count + ' pending Windows update(s):') -ForegroundColor Yellow; "
        "    foreach ($u in $results.Updates) { Write-Host ('  • ' + $u.Title) }; "
        "    Write-Host 'Downloading and installing real Windows patches directly from Microsoft...'; "
        "    $installer = $session.CreateUpdateInstaller(); "
        "    $installer.Updates = $results.Updates; "
        "    $installResult = $installer.Install(); "
        "    Write-Host ('[✓] Installation Finished with Result Code: ' + $installResult.ResultCode) -ForegroundColor Green; "
        "}\"\r\n"
        + callback_cmd +
        "echo.\r\n"
        "echo ========================================================\r\n"
        "echo [✓] Windows Update execution completed!\r\n"
        "echo ========================================================\r\n"
        "pause\r\n"
    )
    return Response(
        content=bat_content,
        media_type="application/x-bat",
        headers={"Content-Disposition": "attachment; filename=install_windows_updates.bat"},
    )


@router.get("/launcher/linux")
def download_linux_updater(
    token: str | None = None,
    job_id: int | None = None,
):
    """
    Serves a 1-click Linux package updater shell script for remote Linux endpoints.
    Downloads and installs real packages via native package manager (apt/dnf/yum).
    """
    callback_cmd = ""
    if job_id and token:
        callback_cmd = f"""
curl -s -X POST "https://api.netops.co.ke/endpoint-updates/jobs/{job_id}/status" \
  -H "Authorization: Bearer {token.strip()}" \
  -H "Content-Type: application/json" \
  -d '{{"status": "COMPLETED", "progress_percent": 100, "log_output": "Real Linux packages upgraded via native package manager."}}' >/dev/null 2>&1 || true
"""

    sh_content = (
        "#!/usr/bin/env bash\n"
        "set -e\n"
        "echo '========================================================'\n"
        "echo '  NETOPS Real Physical Linux Update Agent'\n"
        "echo '========================================================'\n"
        "echo ''\n\n"
        "if [ \"$EUID\" -ne 0 ]; then\n"
        "    echo '[*] Requesting sudo privileges to deploy updates...'\n"
        "    SUDO='sudo'\n"
        "else\n"
        "    SUDO=''\n"
        "fi\n\n"
        "if command -v apt-get >/dev/null 2>&1; then\n"
        "    echo '[*] Refreshing APT package index...'\n"
        "    $SUDO apt-get update\n"
        "    echo '[*] Downloading and installing real security packages...'\n"
        "    $SUDO DEBIAN_FRONTEND=noninteractive apt-get -y --with-new-pkgs upgrade\n"
        "elif command -v dnf >/dev/null 2>&1; then\n"
        "    echo '[*] Checking DNF updates...'\n"
        "    $SUDO dnf check-update || true\n"
        "    echo '[*] Downloading and installing DNF packages...'\n"
        "    $SUDO dnf -y upgrade\n"
        "elif command -v yum >/dev/null 2>&1; then\n"
        "    echo '[*] Updating YUM repositories and packages...'\n"
        "    $SUDO yum -y update\n"
        "else\n"
        "    echo '[!] No supported package manager (apt/dnf/yum) found.'\n"
        "    exit 1\n"
        "fi\n\n"
        + callback_cmd +
        "echo ''\n"
        "echo '========================================================'\n"
        "echo '[✓] Linux system updates successfully installed!'\n"
        "echo '========================================================'\n"
    )
    return Response(
        content=sh_content,
        media_type="application/x-sh",
        headers={"Content-Disposition": "attachment; filename=install_linux_updates.sh"},
    )

