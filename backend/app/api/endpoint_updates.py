from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.endpoint_update import EndpointUpdate
from ..models.device import Device
from ..models.patch_job import PatchJob
from ..schemas.patch_job import (
    CreatePatchJobRequest,
    UpdateJobStatusRequest,
    PatchJobResponse,
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



    endpoint_update = EndpointUpdate(
        hostname=report.hostname,
        mac_address=report.mac_address,
        ip_address=report.ip_address,
        machine_id=report.machine_id,
        operating_system=report.operating_system,
        os_version=report.os_version,
        architecture=report.architecture,
        update_status=report.update_status,
        pending_updates=report.pending_updates,
        security_updates=report.security_updates,
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
    }


@router.get("/")
def get_endpoint_updates(
    db: Session = Depends(get_db),
):
    endpoint_updates = (
        db.query(EndpointUpdate)
        .order_by(
            EndpointUpdate.last_checked.desc(),
        )
        .all()
    )

    seen_machine_ids = set()
    seen_macs = set()
    seen_hostnames = set()
    results = []

    for endpoint in endpoint_updates:
        norm_mac = (
            endpoint.mac_address.replace(":", "").replace("-", "").upper()
            if endpoint.mac_address
            else None
        )
        norm_host = endpoint.hostname.lower().strip() if endpoint.hostname else None

        is_seen = (
            (endpoint.machine_id and endpoint.machine_id in seen_machine_ids)
            or (norm_mac and norm_mac in seen_macs)
            or (norm_host and norm_host in seen_hostnames)
        )
        if is_seen:
            continue

        results.append(endpoint)
        if endpoint.machine_id:
            seen_machine_ids.add(endpoint.machine_id)
        if norm_mac:
            seen_macs.add(norm_mac)
        if norm_host:
            seen_hostnames.add(norm_host)

    # ---------------------------------------------------------
    # Match endpoint reports to discovered LAN devices
    # ---------------------------------------------------------

    devices = db.scalars(
        select(Device)
    ).all()

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

    enriched_results = []

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

        is_online = (device.status == "online") if device else False
        update_status = endpoint.update_status
        if is_online and update_status in ("stale", "unknown"):
            update_status = "updates_available" if (device and device.device_type == "computer") else "up_to_date"

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
                "pending_updates": endpoint.pending_updates,
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
        if device.status != "online":
            continue
        dev_mac = (device.mac_address or "").replace(":", "").replace("-", "").upper()
        if (dev_mac and dev_mac in seen_macs_in_enriched) or (device.ip_address and device.ip_address in seen_ips_in_enriched):
            continue

        enriched_results.append({
            "id": f"dev-{device.id}",
            "hostname": device.hostname or f"HOST-{device.ip_address or device.id}",
            "mac_address": device.mac_address,
            "ip_address": device.ip_address,
            "machine_id": dev_mac or f"lan-{device.id}",
            "operating_system": getattr(device, "operating_system", "Generic Network Device") or "Generic Network Device",
            "os_version": getattr(device, "os_version", "") or "Online",
            "architecture": "AMD64",
            "update_status": getattr(device, "update_status", None) or ("updates_available" if device.device_type == "computer" else "up_to_date"),
            "pending_updates": getattr(device, "pending_updates", 0) or 0,
            "security_updates": None,
            "last_checked": getattr(device, "last_update_check", None) or datetime.now(timezone.utc),
            "is_online": True,
            "device_id": device.id,
            "device_ip": device.ip_address,
            "device_type": device.device_type,
            "device_status": "online",
            "approval_status": device.approval_status,
            "enforcement_status": device.enforcement_status,
            "internet_access_authorized": device.internet_access_authorized,
        })

    return enriched_results


class LanScanRequest(BaseModel):
    network: str | None = None


@router.post("/scan-lan")
def run_lan_patch_scan(
    payload: LanScanRequest | None = None,
    db: Session = Depends(get_db),
):
    """
    Agentless LAN scan: discovers all machines connected to the same LAN
    and evaluates their update/patch status directly from the central machine.
    """
    target_net = payload.network if payload else None
    try:
        results = scan_lan_for_updates(network=target_net, db=db)
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
):
    """
    Queue an update deployment job for an endpoint.
    If the target is the local host, starts native update execution immediately.
    If remote, queues command for the machine's agent to execute on check-in.
    """
    try:
        job, is_local = create_patch_job(
            db=db,
            hostname=payload.hostname,
            ip_address=payload.ip_address,
            mac_address=payload.mac_address,
            machine_id=payload.machine_id,
            device_id=payload.device_id,
            action=payload.action,
            initiated_by=payload.initiated_by,
            scheduled_at=payload.scheduled_at,
        )
        resp = PatchJobResponse.model_validate(job)
        resp.is_local = is_local
        return resp
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create update job: {exc}",
        ) from exc


@router.get("/jobs", response_model=list[PatchJobResponse])
def get_patch_jobs(
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """List recent update deployment jobs and their status."""
    jobs = list_patch_jobs(db, limit=limit, offset=offset)
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


@router.delete("/jobs/{job_id}")
def delete_patch_job(
    job_id: int,
    db: Session = Depends(get_db),
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

