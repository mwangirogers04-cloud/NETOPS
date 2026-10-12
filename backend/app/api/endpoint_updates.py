from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.endpoint_update import EndpointUpdate
from ..models.device import Device
from ..services.event_service import create_event

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

    latest_by_machine_id = {}
    latest_by_hostname = {}

    for endpoint in endpoint_updates:
        if endpoint.machine_id:
            if endpoint.machine_id not in latest_by_machine_id:
                latest_by_machine_id[endpoint.machine_id] = endpoint
        else:
            if endpoint.hostname not in latest_by_hostname:
                latest_by_hostname[endpoint.hostname] = endpoint

    results = list(latest_by_machine_id.values())

    machine_id_hostnames = {
        endpoint.hostname
        for endpoint in latest_by_machine_id.values()
    }

    for hostname, endpoint in latest_by_hostname.items():
        if hostname not in machine_id_hostnames:
            results.append(endpoint)

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

        device = devices_by_mac.get(endpoint_mac)

        enriched_results.append(
            {
                "id": endpoint.id,
                "hostname": endpoint.hostname,
                "mac_address": endpoint.mac_address,
                "ip_address": endpoint.ip_address,
                "machine_id": endpoint.machine_id,
                "operating_system": endpoint.operating_system,
                "os_version": endpoint.os_version,
                "architecture": endpoint.architecture,
                "update_status": endpoint.update_status,
                "pending_updates": endpoint.pending_updates,
                "security_updates": endpoint.security_updates,
                "last_checked": endpoint.last_checked,
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

    return enriched_results
