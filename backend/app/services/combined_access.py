from sqlalchemy.orm import Session
from datetime import datetime

from ..models.device import Device
from ..models.access_schedule import AccessSchedule
from .access_policy import normalize_device_type
from .access_schedule import is_access_allowed
from .device_classifier import classify_device


def get_combined_access_decision(
    device: Device,
    db: Session,
    current_datetime: datetime | None = None,
) -> dict:
    """
    Calculate the final simulated Internet access decision
    using device approval status and access schedule.

    This function does NOT modify Sophos, Cisco, VLANs,
    or any real network configuration.
    """

    has_active_schedule = False
    try:
        schedule_records = db.query(AccessSchedule).filter(
            AccessSchedule.device_id == device.id,
            AccessSchedule.enabled.is_(True),
        ).all()
        if isinstance(schedule_records, (list, tuple)):
            has_active_schedule = len(schedule_records) > 0
    except Exception:
        has_active_schedule = False

    schedule_allows_access = is_access_allowed(
        db,
        device.id,
        current_datetime=current_datetime,
    )

    recognized_type = normalize_device_type(device.device_type)
    if not recognized_type:
        classified = classify_device(
            hostname=getattr(device, "hostname", None),
            vendor=getattr(device, "vendor", None),
            mac_address=getattr(device, "mac_address", None),
        )
        recognized_type = normalize_device_type(classified)

    # ---------------------------------------------------------
    # 1. Active schedule takes precedence for recognized devices
    # ---------------------------------------------------------
    if has_active_schedule:
        if schedule_allows_access and recognized_type:
            return {
                "device_id": device.id,
                "ip_address": device.ip_address,
                "mac_address": device.mac_address,
                "approval_status": "approved",
                "schedule_allows_access": True,
                "decision": "allowed",
                "reason": "approved_and_within_schedule",
                "action": "allow",
                "mode": "simulation",
            }
        elif not schedule_allows_access:
            return {
                "device_id": device.id,
                "ip_address": device.ip_address,
                "mac_address": device.mac_address,
                "approval_status": device.approval_status,
                "schedule_allows_access": False,
                "decision": "quarantine",
                "reason": "outside_access_schedule",
                "action": "quarantine",
                "mode": "simulation",
            }
        else:
            return {
                "device_id": device.id,
                "ip_address": device.ip_address,
                "mac_address": device.mac_address,
                "approval_status": device.approval_status,
                "schedule_allows_access": True,
                "decision": "quarantine",
                "reason": "unrecognized_device_type",
                "action": "quarantine",
                "mode": "simulation",
            }

    # ---------------------------------------------------------
    # 2. Check device approval status (without schedule)
    # ---------------------------------------------------------
    if device.approval_status in {"pending", "rejected"}:
        return {
            "device_id": device.id,
            "ip_address": device.ip_address,
            "mac_address": device.mac_address,
            "approval_status": device.approval_status,
            "schedule_allows_access": False,
            "decision": "quarantine",
            "reason": "device_not_approved",
            "action": "quarantine",
            "mode": "simulation",
        }

    # ---------------------------------------------------------
    # 3. Approved device without schedule
    # ---------------------------------------------------------
    decision = "allowed" if recognized_type else "quarantine"
    action = "allow" if decision == "allowed" else "quarantine"
    reason = "approved_recognized_device" if decision == "allowed" else "unrecognized_device_type"

    return {
        "device_id": device.id,
        "ip_address": device.ip_address,
        "mac_address": device.mac_address,
        "approval_status": device.approval_status,
        "schedule_allows_access": schedule_allows_access,
        "decision": decision,
        "reason": reason,
        "action": action,
        "mode": "simulation",
    }
