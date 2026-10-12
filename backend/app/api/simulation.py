from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.device import Device
from ..services.device_classifier import classify_device
from ..services.event_service import create_event
from ..services.vlan_policy import get_vlan_for_device_type

router = APIRouter(prefix="/simulation", tags=["Simulation"])

SIMULATION_NOTE = (
    "NETOPS SIMULATION: fictional test device; "
    "not discovered on the physical LAN."
)

SAMPLE_DEVICES = [
    {
        "mac_address": "02:4E:45:54:4F:01",
        "ip_address": "192.0.2.101",
        "hostname": "SIM-PC-01",
        "vendor": "Dell",
    },
    {
        "mac_address": "02:4E:45:54:4F:02",
        "ip_address": "192.0.2.102",
        "hostname": "SIM-CCTV-01",
        "vendor": "Hikvision",
    },
    {
        "mac_address": "02:4E:45:54:4F:03",
        "ip_address": "192.0.2.103",
        "hostname": "SIM-PRINTER-01",
        "vendor": "Brother",
    },
    {
        "mac_address": "02:4E:45:54:4F:04",
        "ip_address": "192.0.2.104",
        "hostname": "SIM-UNKNOWN-01",
        "vendor": "Unidentified Test Vendor",
    },
]


@router.post("/seed")
def seed_simulation_devices(db: Session = Depends(get_db)):
    """Create fictional devices without accessing physical equipment."""

    existing_by_mac = {}

    # Validate all existing MAC addresses before making changes.
    for sample in SAMPLE_DEVICES:
        existing = db.scalar(
            select(Device).where(
                Device.mac_address == sample["mac_address"]
            )
        )

        if existing is not None:
            if not (
                existing.notes
                and "NETOPS SIMULATION:" in existing.notes
            ):
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "A sample MAC address belongs to a "
                        "non-simulation device. No devices were created."
                    ),
                )

            existing_by_mac[sample["mac_address"]] = existing

    created = []
    already_present = []

    try:
        for sample in SAMPLE_DEVICES:
            mac_address = sample["mac_address"]

            if mac_address in existing_by_mac:
                already_present.append(mac_address)
                continue

            detected_type = classify_device(
                hostname=sample["hostname"],
                vendor=sample["vendor"],
                mac_address=mac_address,
            )

            device = Device(
                **sample,
                device_type=(
                    None if detected_type == "unknown"
                    else detected_type
                ),
                vlan_id=get_vlan_for_device_type(detected_type),
                classification_status="normal",
                status="online",
                approval_status="pending",
                enforcement_status="quarantined",
                internet_access_authorized=False,
                notes=SIMULATION_NOTE,
            )

            db.add(device)
            db.flush()

            create_event(
                db,
                "simulation_device_created",
                (
                    f"SIMULATION ONLY: created fictional device "
                    f"{device.hostname}, type={detected_type}, "
                    f"target VLAN={device.vlan_id}. "
                    "Device remains pending and quarantined."
                ),
                device.id,
            )

            created.append(device)

        db.commit()

    except Exception:
        db.rollback()
        raise

    return {
        "mode": "simulation",
        "hardware_accessed": False,
        "created_count": len(created),
        "already_present_count": len(already_present),
        "created": [
            {
                "id": device.id,
                "hostname": device.hostname,
                "mac_address": device.mac_address,
                "device_type": device.device_type or "unknown",
                "vlan_id": device.vlan_id,
                "approval_status": device.approval_status,
                "enforcement_status": device.enforcement_status,
            }
            for device in created
        ],
        "already_present": already_present,
    }
