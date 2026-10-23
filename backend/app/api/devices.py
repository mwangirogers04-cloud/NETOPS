from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.device import Device
from ..models.endpoint_update import EndpointUpdate
from ..models.access_schedule import AccessSchedule
from ..schemas.device import (
    DeviceCreate,
    DeviceResponse,
    DeviceTypeUpdate,
    DeviceVlanUpdate,
    DeviceIpAssignmentUpdate,
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

    if not getattr(device, "ip_assignment", None):
        device.ip_assignment = "dhcp"

    if device.enforcement_status == "isolated":
        device.access_decision = "isolated"

    elif device.approval_status in {"pending", "rejected"}:
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

    if device.enforcement_status == "isolated":
        device.access_reason = (
            "Device is explicitly isolated from the network (VLAN 90)"
        )

    elif device.approval_status in {"pending", "rejected"}:
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

    if not hasattr(device, "update_status") or device.update_status is None:
        device.update_status = "unmonitored"
        device.pending_updates = None
        device.security_updates = None
        device.last_update_check = None
        device.operating_system = None
        device.os_version = None

    return device


def attach_update_information(devices: list[Device], db: Session):
    """
    Attach the latest endpoint update telemetry to each device.
    Matches primarily by normalized MAC address, with IP fallback.
    """
    if not devices:
        return devices

    endpoint_updates = (
        db.query(EndpointUpdate)
        .order_by(EndpointUpdate.last_checked.desc())
        .all()
    )

    mac_to_update = {}
    ip_to_update = {}

    for report in endpoint_updates:
        if report.mac_address:
            norm_mac = (
                report.mac_address.replace(":", "").replace("-", "").upper()
            )
            if norm_mac not in mac_to_update:
                mac_to_update[norm_mac] = report

        if report.ip_address and report.ip_address not in ip_to_update:
            ip_to_update[report.ip_address] = report

    for device in devices:
        matched_report = None
        if device.mac_address:
            norm_dev_mac = (
                device.mac_address.replace(":", "").replace("-", "").upper()
            )
            matched_report = mac_to_update.get(norm_dev_mac)

        if not matched_report and device.ip_address:
            matched_report = ip_to_update.get(device.ip_address)

        if matched_report:
            if not device.hostname and matched_report.hostname:
                device.hostname = matched_report.hostname
            device.update_status = matched_report.update_status
            device.pending_updates = matched_report.pending_updates
            device.security_updates = matched_report.security_updates
            device.last_update_check = matched_report.last_checked
            device.operating_system = matched_report.operating_system
            device.os_version = matched_report.os_version
        else:
            device.update_status = "unmonitored"
            device.pending_updates = None
            device.security_updates = None
            device.last_update_check = None
            device.operating_system = None
            device.os_version = None

    return devices


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

    attach_update_information(devices, db)

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
    device.internet_access_authorized = False
    device.enforcement_status = "quarantined"

    # Rejected devices return to quarantine VLAN.
    device.vlan_id = 90

    enforce_device_access(
        device,
        db,
        force=True,
    )

    create_event(
        db,
        "device_rejected",
        (
            f"Device rejected by administrator: "
            f"{device.hostname or 'Unknown Device'} "
            f"({device.ip_address or 'No IP'}) "
            f"MAC {device.mac_address}. "
            f"Device placed in VLAN 90 quarantine and internet disconnected."
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
    # RESTORE OPERATIONAL VLAN IF CURRENTLY IN QUARANTINE
    # --------------------------------------------------------
    if device.vlan_id == 90 or not device.vlan_id:
        target_vlan = get_vlan_for_device_type(device.device_type)
        if not target_vlan or target_vlan == 90:
            target_vlan = 20
            if not device.device_type or device.device_type == "unknown":
                device.device_type = "computer"
        device.vlan_id = target_vlan

    # --------------------------------------------------------
    # EXPLICIT INTERNET ACCESS GRANT
    # --------------------------------------------------------

    if device.enforcement_status == "isolated":
        device.enforcement_status = "quarantined"

    device.internet_access_authorized = True
    result = enforce_device_access(
        device,
        db,
        force=True,
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

    # When manually disconnected, disable active access schedules so the manual
    # disconnect is respected
    try:
        active_schedules = (
            db.query(AccessSchedule)
            .filter(
                AccessSchedule.device_id == device.id,
                AccessSchedule.enabled.is_(True),
            )
            .all()
        )
        for sch in active_schedules:
            sch.enabled = False
    except Exception:
        pass

    result = enforce_device_access(
        device,
        db,
        force=True,
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

    if new_type in ("phone", "voip", "ipphone"):
        new_type = "ip_phone"
    elif new_type in ("ap", "wap", "wifi_ap", "accesspoint"):
        new_type = "access_point"
    elif new_type in ("servers",):
        new_type = "server"

    allowed_types = {
        "ip_phone",
        "computer",
        "cctv",
        "printer",
        "server",
        "access_point",
        "unknown",
    }

    if new_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid device type. "
                "Allowed values: "
                "ip_phone, computer, cctv, printer, server, access_point, unknown"
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
    # AUTOMATIC QUARANTINE ON VLAN 90 / UNKNOWN
    # --------------------------------------------------------
    if new_vlan == 90 or new_type == "unknown":
        device.internet_access_authorized = False
        device.enforcement_status = "quarantined"
        enforce_device_access(
            device,
            db,
            force=True,
        )

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
        force=True,
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

    if device.vlan_id == 90 or result.get("vlan_id") == 90:
        device.internet_access_authorized = False
        device.enforcement_status = "quarantined"
        enforce_device_access(
            device,
            db,
            force=True,
        )

    db.commit()
    db.refresh(device)

    add_access_information(device)

    return result


# ------------------------------------------------------------
# UPDATE DEVICE VLAN
# ------------------------------------------------------------

@router.patch(
    "/{device_id}/vlan",
    response_model=DeviceResponse,
)
def set_device_vlan(
    device_id: int,
    vlan_data: DeviceVlanUpdate,
    db: Session = Depends(get_db),
):
    device = db.get(Device, device_id)

    if device is None:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    old_vlan = device.vlan_id
    new_vlan = vlan_data.vlan_id

    allowed_vlans = {10, 20, 30, 40, 50, 60, 90}
    if new_vlan not in allowed_vlans:
        raise HTTPException(
            status_code=400,
            detail="Invalid VLAN ID. Allowed VLANs: 10 (IP Phones), 20 (Computers), 30 (CCTV), 40 (Printers), 50 (Servers), 60 (Access Points), 90 (Quarantine)",
        )

    device.vlan_id = new_vlan

    # If moving to Quarantine VLAN 90, automatically disconnect internet access immediately
    if new_vlan == 90:
        device.internet_access_authorized = False
        device.enforcement_status = "quarantined"
        enforce_device_access(
            device,
            db,
            force=True,
        )
        create_event(
            db,
            "vlan_quarantine",
            (
                f"Device {device.hostname or 'Unknown Device'} "
                f"({device.ip_address or 'No IP'}) "
                f"placed in Quarantine VLAN 90. Internet access automatically disconnected."
            ),
            device.id,
        )
    else:
        if device.enforcement_status == "isolated":
            device.enforcement_status = "quarantined"
        create_event(
            db,
            "vlan_change",
            (
                f"Device {device.hostname or 'Unknown Device'} "
                f"({device.ip_address or 'No IP'}) "
                f"moved from VLAN {old_vlan or 90} to VLAN {new_vlan}."
            ),
            device.id,
        )
        if device.approval_status == "approved" and device.internet_access_authorized:
            enforce_device_access(
                device,
                db,
                force=True,
            )

    db.commit()
    db.refresh(device)

    add_access_information(device)

    return device


# ------------------------------------------------------------
# UPDATE DEVICE IP ASSIGNMENT (DHCP vs STATIC)
# ------------------------------------------------------------

@router.patch(
    "/{device_id}/ip-assignment",
    response_model=DeviceResponse,
)
def set_device_ip_assignment(
    device_id: int,
    assignment_data: DeviceIpAssignmentUpdate,
    db: Session = Depends(get_db),
):
    device = db.get(Device, device_id)

    if device is None:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    val = assignment_data.ip_assignment.lower().strip()
    if val not in ("dhcp", "static"):
        raise HTTPException(
            status_code=400,
            detail="Invalid IP assignment. Allowed values: 'dhcp', 'static'",
        )

    old_val = getattr(device, "ip_assignment", "dhcp")
    device.ip_assignment = val

    create_event(
        db,
        "device_configuration",
        (
            f"Device {device.hostname or device.ip_address or device.mac_address} "
            f"IP assignment type updated from {old_val.upper()} to {val.upper()}."
        ),
        device.id,
    )

    db.commit()
    db.refresh(device)

    add_access_information(device)

    return device


# ------------------------------------------------------------
# ISOLATE DEVICE
# ------------------------------------------------------------

@router.post(
    "/{device_id}/isolate",
    response_model=DeviceResponse,
)
def isolate_device(
    device_id: int,
    db: Session = Depends(get_db),
):
    device = db.get(Device, device_id)

    if device is None:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    old_vlan = device.vlan_id

    device.enforcement_status = "isolated"
    device.internet_access_authorized = False
    device.vlan_id = 90

    # Disable active access schedules while device is explicitly isolated
    try:
        active_schedules = (
            db.query(AccessSchedule)
            .filter(
                AccessSchedule.device_id == device.id,
                AccessSchedule.enabled.is_(True),
            )
            .all()
        )
        for sch in active_schedules:
            sch.enabled = False
    except Exception:
        pass

    enforce_device_access(
        device,
        db,
        force=True,
    )

    create_event(
        db,
        "device_isolated",
        (
            f"Device isolated by administrator: "
            f"{device.hostname or 'Unknown Device'} "
            f"({device.ip_address or 'No IP'}) "
            f"MAC {device.mac_address}. "
            f"Moved from VLAN {old_vlan or 90} to Quarantine VLAN 90 and network/internet access blocked."
        ),
        device.id,
    )

    db.commit()
    db.refresh(device)

    attach_update_information([device], db)
    add_access_information(device)

    return device


# ------------------------------------------------------------
# UNISOLATE / RELEASE DEVICE FROM ISOLATION
# ------------------------------------------------------------

@router.post(
    "/{device_id}/unisolate",
    response_model=DeviceResponse,
)
def unisolate_device(
    device_id: int,
    db: Session = Depends(get_db),
):
    device = db.get(Device, device_id)

    if device is None:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    device.enforcement_status = "quarantined"

    if device.approval_status == "approved":
        target_vlan = get_vlan_for_device_type(device.device_type)
        if not target_vlan or target_vlan == 90:
            target_vlan = 20
            if not device.device_type or device.device_type == "unknown":
                device.device_type = "computer"
        device.vlan_id = target_vlan
    else:
        device.vlan_id = 90

    enforce_device_access(
        device,
        db,
        force=True,
    )

    create_event(
        db,
        "device_unisolated",
        (
            f"Device released from isolation by administrator: "
            f"{device.hostname or 'Unknown Device'} "
            f"({device.ip_address or 'No IP'}) "
            f"MAC {device.mac_address}. "
            f"Assigned to VLAN {device.vlan_id}."
        ),
        device.id,
    )

    db.commit()
    db.refresh(device)

    attach_update_information([device], db)
    add_access_information(device)

    return device


# ------------------------------------------------------------
# RESET / RE-TEST DEVICE FOR LAN CONNECTION EXPERIMENT
# ------------------------------------------------------------

@router.post(
    "/{device_id}/reset-experiment",
    response_model=DeviceResponse,
)
def reset_device_for_experiment(
    device_id: int,
    db: Session = Depends(get_db),
):
    """
    Reset a device back to its initial newly-connected LAN state
    (approval_status='pending', vlan_id=90, enforcement_status='quarantined',
    internet_access_authorized=False) and emit a real-time new_device LAN
    connection notification event so the administrator can step through
    the full onboarding & enforcement experiment from Step 1.
    """
    device = db.get(Device, device_id)

    if device is None:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    device.approval_status = "pending"
    device.classification_status = "normal"
    device.vlan_id = 90
    device.enforcement_status = "quarantined"
    device.internet_access_authorized = False

    try:
        enforce_device_access(device, db, force=True)
    except Exception:
        pass

    create_event(
        db,
        "new_device",
        (
            f"Machine connected to LAN ({device.network_interface or 'eth0'}): "
            f"{device.hostname or 'Experimental Machine'} "
            f"({device.ip_address or 'No IP'} / {device.mac_address}) "
            f"[{device.vendor or 'LAN Endpoint'}] — "
            f"Placed in VLAN 90 Quarantine. Awaiting administrator review & approval."
        ),
        device.id,
    )

    db.commit()
    db.refresh(device)

    attach_update_information([device], db)
    add_access_information(device)

    return device



