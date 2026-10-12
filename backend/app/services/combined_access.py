from sqlalchemy.orm import Session
from datetime import datetime

from ..models.device import Device
from .access_schedule import is_access_allowed


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

    # ---------------------------------------------------------
    # 1. Check device approval status
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
    # 2. Check access schedule
    # ---------------------------------------------------------
    schedule_allows_access = is_access_allowed(
    db,
    device.id,
    current_datetime=current_datetime,
)

    # ---------------------------------------------------------
    # 3. Combine approval + schedule decision
    # ---------------------------------------------------------

    if schedule_allows_access:
        decision = "allowed"
        action = "allow"
        reason = "approved_and_within_schedule"

    else:
        decision = "quarantine"
        action = "quarantine"
        reason = "outside_access_schedule"

    # ---------------------------------------------------------
    # 4. Return final simulated decision
    # ---------------------------------------------------------

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
