from datetime import datetime
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.device import Device
from ..models.event import Event
from .access_policy import get_access_decision
from .access_schedule import is_access_allowed
from .event_service import create_event


def enforce_device_access(
    device: Device,
    db: Session,
    current_datetime: datetime | None = None,
) -> dict:
    """
    Calculate and record the current network enforcement state.

    NETOPS is currently operating in simulation mode.

    Approval determines whether the device is eligible
    for network access.

    enforcement_status records the current simulated
    network state.

    Therefore:

        approved + recognized device
            -> allowed

        pending/rejected/unknown device
            -> quarantined
    """

    old_enforcement_status = (
        device.enforcement_status
    )

    # ---------------------------------------------------------
    # Determine access from approval, authorization,
    # device classification, and access schedule.
    # ---------------------------------------------------------

    if device.approval_status in {"pending", "rejected"}:
        decision = "quarantine"

    elif not device.internet_access_authorized:
        # Approval does NOT automatically grant Internet access.
        # The administrator must explicitly authorize access.
        decision = "quarantine"

    else:
        decision = get_access_decision(
            device.device_type,
            device.approval_status,
        )

        if decision == "allowed":
            schedule_allows_access = is_access_allowed(
                db,
                device.id,
                current_datetime=current_datetime,
            )

            if not schedule_allows_access:
                decision = "quarantine"

    # ---------------------------------------------------------
    # Determine the simulated enforcement action.
    # ---------------------------------------------------------

    if decision == "allowed":
        action = "allow"
        enforcement_status = "allowed"

        message = (
            f"Internet access allowed for device "
            f"{device.ip_address} "
            f"({device.mac_address}) "
            f"on VLAN {device.vlan_id}"
        )

    else:
        action = "quarantine"
        enforcement_status = "quarantined"

        message = (
            f"Internet access blocked for device "
            f"{device.ip_address} "
            f"({device.mac_address}) "
            f"on VLAN {device.vlan_id}"
        )

    # ---------------------------------------------------------
    # Store current enforcement state.
    # ---------------------------------------------------------

    device.enforcement_status = (
        enforcement_status
    )

    # ---------------------------------------------------------
    # Audit event.
    # ---------------------------------------------------------

    latest_event = db.scalar(
        select(Event)
        .where(
            Event.device_id == device.id,
            Event.event_type == "access_enforcement",
        )
        .order_by(Event.id.desc())
        .limit(1)
    )

    if (
        latest_event is None
        or latest_event.message != message
    ):
        create_event(
            db,
            "access_enforcement",
            message,
            device.id,
        )

    # ---------------------------------------------------------
    # Return result.
    # ---------------------------------------------------------

    return {
        "device_id": device.id,
        "ip_address": device.ip_address,
        "mac_address": device.mac_address,
        "device_type": device.device_type,
        "approval_status": device.approval_status,
        "vlan_id": device.vlan_id,
        "decision": decision,
        "action": action,
        "enforcement_status": (
            device.enforcement_status
        ),
        "previous_enforcement_status": (
            old_enforcement_status
        ),
        "mode": "simulation",
    }
