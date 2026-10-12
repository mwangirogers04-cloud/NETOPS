from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.device import Device
from ..schemas.device import (
    DeviceCreate,
    DeviceResponse,
    DeviceTypeUpdate,
)
from ..services.vlan_policy import get_vlan_for_device_type
from ..services.access_policy import (
    get_access_decision,
    get_access_reason,
)
from ..services.network_enforcement import enforce_device_access
from ..services.vlan_automation import automate_vlan_assignment
from ..services.event_service import create_event


router = APIRouter(
    prefix="/devices",
    tags=["Devices"],
)


# ------------------------------------------------------------
# ACCESS INFORMATION
# ------------------------------------------------------------

def add_access_information(device: Device):
    """
    Calculate the logical access decision shown by the API.

    Approval and Internet access are separate concepts.
    """

    if device.approval_status in {"pending", "rejected"}:
        device.access_decision = "quarantine"

    elif device.enforcement_status == "allowed":
        device.access_decision = "allowed"

    else:
        device.access_decision = "quarantine"

    # Explain the actual access state, not just approval eligibility.
    reason = get_access_reason(
        device.device_type,
        device.approval_status,
    )

    if device.approval_status in {"pending", "rejected"}:
        device.access_reason = reason

    elif reason == "Unknown or unrecognized device type":
        device.access_reason = reason

    elif not device.internet_access_authorized:
        device.access_reason = (
            "Internet access has not been explicitly authorized"
        )

    elif device.enforcement_status != "allowed":
        device.access_reason = (
            "Internet access is currently quarantined by policy or schedule"
        )

    else:
        device.access_reason = (
            "Approved recognized device with internet access allowed"
        )

    return device

# ------------------------------------------------------------
# GET ALL DEVICES
# ------------------------------------------------------------

@router.get(
    "/",
    response_model=list[DeviceResponse],
)
def get_devices(
    db: Session = Depends(get_db),
):
    devices = db.scalars(
        select(Device).order_by(Device.id)
    ).all()

    for device in devices:
        add_access_information(device)

    return devices


# ------------------------------------------------------------
# CREATE / DISCOVER DEVICE
# ------------------------------------------------------------

@router.post(
    "/",
    response_model=DeviceResponse,
    status_code=201,
)
def create_device(
    device_data: DeviceCreate,
    db: Session = Depends(get_db),
):
    existing_device = db.scalar(
        select(Device).where(
            Device.mac_address == device_data.mac_address
        )
    )

    if existing_device:
        raise HTTPException(
            status_code=409,
            detail="Device with this MAC address already exists",
        )

    # --------------------------------------------------------
    # EVERY NEW DEVICE STARTS IN QUARANTINE
    # --------------------------------------------------------

    device = Device(
        **device_data.model_dump(
            exclude={"vlan_id"}
        ),
        status="online",
        approval_status="pending",
        classification_status="normal",

        # Unknown/new devices always start in VLAN 90.
        vlan_id=90,

        # New devices are blocked until explicitly allowed.
        enforcement_status="quarantined",
    )

    db.add(device)
    db.commit()
    db.refresh(device)

    # Create discovery event.
    create_event(
        db,
        "device_detected",
        (
            f"New device detected: "
            f"{device.hostname or 'Unknown Device'} "
            f"({device.ip_address or 'No IP'}) "
            f"MAC {device.mac_address}. "
            f"Placed in VLAN 90 quarantine. "
            f"Awaiting administrator approval."
        ),
        device.id,
    )

    db.commit()
    db.refresh(device)

    add_access_information(device)

    return device


# ------------------------------------------------------------
# APPROVE DEVICE
# ------------------------------------------------------------

@router.patch(
    "/{device_id}/approve",
    response_model=DeviceResponse,
)
def approve_device(
    device_id: int,
    db: Session = Depends(get_db),
):
    device = db.get(Device, device_id)

    if device is None:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    if device.approval_status == "approved":
        raise HTTPException(
            status_code=400,
            detail="Device is already approved",
        )

    # --------------------------------------------------------
    # APPROVAL DOES NOT GRANT INTERNET ACCESS
    # --------------------------------------------------------

    device.approval_status = "approved"

    # Keep the device blocked until the administrator
    # explicitly clicks "Allow Internet".
    device.enforcement_status = "quarantined"

    create_event(
        db,
        "device_approved",
        (
            f"Device approved by administrator: "
            f"{device.hostname or 'Unknown Device'} "
            f"({device.ip_address or 'No IP'}) "
            f"MAC {device.mac_address}. "
            f"Internet access remains blocked pending "
            f"explicit authorization."
        ),
        device.id,
    )

    # --------------------------------------------------------
    # AUTOMATE VLAN ASSIGNMENT
    # --------------------------------------------------------
    # VLAN automation is simulation-only for now.
    # Approval does NOT grant Internet access.
    vlan_result = automate_vlan_assignment(
        device,
        db,
    )
    db.commit()
    db.refresh(device)

    add_access_information(device)

    return device


# ------------------------------------------------------------
# REJECT DEVICE
# ------------------------------------------------------------

@router.patch(
    "/{device_id}/reject",
    response_model=DeviceResponse,
)
def reject_device(
    device_id: int,
    db: Session = Depends(get_db),
):
    device = db.get(Device, device_id)

    if device is None:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    if device.approval_status == "rejected":
        raise HTTPException(
            status_code=400,
            detail="Device is already rejected",
        )

    device.approval_status = "rejected"

    # Rejected devices must always remain quarantined.
    device.enforcement_status = "quarantined"

    # Rejected devices return to quarantine VLAN.
    device.vlan_id = 90

    create_event(
        db,
        "device_rejected",
        (
            f"Device rejected by administrator: "
            f"{device.hostname or 'Unknown Device'} "
            f"({device.ip_address or 'No IP'}) "
            f"MAC {device.mac_address}. "
            f"Device remains in VLAN 90 quarantine."
        ),
        device.id,
    )

    db.commit()
    db.refresh(device)

    add_access_information(device)

    return device


# ------------------------------------------------------------
# ALLOW INTERNET
# ------------------------------------------------------------

@router.post(
    "/{device_id}/allow",
)
def allow_device(
    device_id: int,
    db: Session = Depends(get_db),
):
    device = db.get(Device, device_id)

    if device is None:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    if device.approval_status != "approved":
        raise HTTPException(
            status_code=400,
            detail=(
                "Device must be approved before "
                "Internet access can be allowed"
            ),
        )

    # --------------------------------------------------------
    # EXPLICIT INTERNET ACCESS GRANT
    # --------------------------------------------------------

    device.internet_access_authorized = True
    result = enforce_device_access(
        device,
        db,
    )

    create_event(
        db,
        "internet_access_allowed",
        (
            f"Internet access allowed for approved device: "
            f"{device.hostname or 'Unknown Device'} "
            f"({device.ip_address or 'No IP'}) "
            f"MAC {device.mac_address}. "
            f"VLAN {device.vlan_id or 90}."
        ),
        device.id,
    )

    db.commit()
    db.refresh(device)

    add_access_information(device)

    return {
        "device_id": device.id,
        "hostname": device.hostname,
        "ip_address": device.ip_address,
        "mac_address": device.mac_address,
        "approval_status": device.approval_status,
        "device_type": device.device_type,
        "vlan_id": device.vlan_id,
        "decision": device.access_decision,
        "action": "allow",
        "enforcement_status": device.enforcement_status,
        "result": result,
    }


# ------------------------------------------------------------
# DISALLOW INTERNET
# ------------------------------------------------------------

@router.post(
    "/{device_id}/disallow",
)
def disallow_device(
    device_id: int,
    db: Session = Depends(get_db),
):
    device = db.get(Device, device_id)

    if device is None:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    # --------------------------------------------------------
    # REMOVE INTERNET ACCESS WITHOUT REJECTING DEVICE
    # --------------------------------------------------------

    device.internet_access_authorized = False

    result = enforce_device_access(
        device,
        db,
    )

    create_event(
        db,
        "internet_access_disallowed",
        (
            f"Internet access disabled for device: "
            f"{device.hostname or 'Unknown Device'} "
            f"({device.ip_address or 'No IP'}) "
            f"MAC {device.mac_address}. "
            f"Device approval status remains "
            f"{device.approval_status}."
        ),
        device.id,
    )

    db.commit()
    db.refresh(device)

    add_access_information(device)

    return {
        "device_id": device.id,
        "hostname": device.hostname,
        "ip_address": device.ip_address,
        "mac_address": device.mac_address,
        "approval_status": device.approval_status,
        "device_type": device.device_type,
        "vlan_id": device.vlan_id,
        "decision": device.access_decision,
        "action": "disallow",
        "enforcement_status": device.enforcement_status,
        "result": result,
    }


# ------------------------------------------------------------
# CLASSIFY DEVICE
# ------------------------------------------------------------

@router.patch(
    "/{device_id}/type",
    response_model=DeviceResponse,
)
def set_device_type(
    device_id: int,
    device_data: DeviceTypeUpdate,
    db: Session = Depends(get_db),
):
    device = db.get(Device, device_id)

    if device is None:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    old_type = device.device_type
    old_vlan = device.vlan_id
    old_review_status = device.classification_status

    new_type = (
        device_data.device_type
        .lower()
        .strip()
    )

    allowed_types = {
        "computer",
        "cctv",
        "printer",
        "unknown",
    }

    if new_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid device type. "
                "Allowed values: "
                "computer, cctv, printer, unknown"
            ),
        )

    if old_type == new_type:
        raise HTTPException(
            status_code=400,
            detail="Device already has this classification",
        )

    # --------------------------------------------------------
    # DEVICE CLASSIFICATION
    # --------------------------------------------------------

    device.device_type = new_type

    new_vlan = get_vlan_for_device_type(
        new_type
    )

    # Safety fallback.
    if new_vlan is None:
        new_vlan = 90

    device.vlan_id = new_vlan

    device.classification_status = "reviewed"

    create_event(
        db,
        "device_classification",
        (
            f"Manual classification change for device "
            f"{device.ip_address or 'No IP'} "
            f"({device.mac_address}): "
            f"{old_type or 'unknown'} -> {new_type}; "
            f"VLAN {old_vlan or 90} -> {new_vlan}"
        ),
        device.id,
    )

    create_event(
        db,
        "classification_review",
        (
            f"Classification review completed for device "
            f"{device.ip_address or 'No IP'} "
            f"({device.mac_address}). "
            f"Previous review status: "
            f"{old_review_status}. "
            f"Final classification: {new_type}. "
            f"Assigned VLAN: {new_vlan}."
        ),
        device.id,
    )

    # --------------------------------------------------------
    # IMPORTANT:
    #
    # Classification must NOT automatically grant Internet.
    #
    # If the device was blocked, it remains blocked.
    # If it was already allowed, it remains allowed.
    # --------------------------------------------------------

    db.commit()
    db.refresh(device)

    add_access_information(device)

    return device


# ------------------------------------------------------------
# ACCESS DECISION
# ------------------------------------------------------------

@router.get(
    "/{device_id}/access-decision",
)
def get_device_access_decision(
    device_id: int,
    db: Session = Depends(get_db),
):
    device = db.get(Device, device_id)

    if device is None:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    add_access_information(device)

    return {
        "device_id": device.id,
        "device_type": device.device_type,
        "approval_status": device.approval_status,
        "classification_status": (
            device.classification_status
        ),
        "vlan_id": device.vlan_id,
        "decision": device.access_decision,
        "enforcement_status": device.enforcement_status,
        "reason": device.access_reason,
    }


# ------------------------------------------------------------
# MANUAL ENFORCEMENT
# ------------------------------------------------------------

@router.post(
    "/{device_id}/enforce",
)
def enforce_device(
    device_id: int,
    db: Session = Depends(get_db),
):
    device = db.get(Device, device_id)

    if device is None:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    # Do not allow manual enforcement to accidentally
    # give Internet access to an unapproved device.
    if device.approval_status != "approved":
        device.enforcement_status = "quarantined"

    result = enforce_device_access(
        device,
        db,
    )

    db.commit()
    db.refresh(device)

    add_access_information(device)

    return result


# ------------------------------------------------------------
# AUTOMATIC VLAN ASSIGNMENT
# ------------------------------------------------------------

@router.post(
    "/{device_id}/automate-vlan",
)
def automate_device_vlan(
    device_id: int,
    db: Session = Depends(get_db),
):
    device = db.get(Device, device_id)

    if device is None:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    result = automate_vlan_assignment(
        device,
        db,
    )

    db.commit()
    db.refresh(device)

    add_access_information(device)

    return result
