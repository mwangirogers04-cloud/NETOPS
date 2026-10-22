from datetime import datetime
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.device import Device
from ..models.event import Event
from ..models.access_schedule import AccessSchedule
from .access_policy import get_access_decision
from .access_schedule import is_access_allowed
from .event_service import create_event
from .firewall.manager import get_active_firewall_driver
from .l2_quarantine import quarantine_device_l2, restore_device_l2
from .sophos_enforcement import (
    is_sophos_configured,
    sophos_block_device,
    sophos_allow_device,
)


def enforce_device_access(
    device: Device,
    db: Session,
    current_datetime: datetime | None = None,
    force: bool = False,
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

    if old_enforcement_status == "isolated":
        # Explicitly isolated devices remain isolated in VLAN 90 with no internet access
        device.internet_access_authorized = False
        device.vlan_id = 90
        decision = "isolated"

    elif device.approval_status in {"pending", "rejected"}:
        decision = "quarantine"

    elif getattr(device, "vlan_id", None) == 90:
        # Devices in Quarantine VLAN 90 are unconditionally quarantined from Internet
        device.internet_access_authorized = False
        decision = "quarantine"

    else:
        # Check if device has an active access schedule
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

        if has_active_schedule:
            schedule_allows_access = is_access_allowed(
                db,
                device.id,
                current_datetime=current_datetime,
            )
            if schedule_allows_access:
                # Active schedule currently allows access -> restore/grant authorization
                decision = "allowed"
                device.internet_access_authorized = True
            else:
                # Active schedule currently outside allowed hours -> quarantine
                decision = "quarantine"
                device.internet_access_authorized = False
        elif not device.internet_access_authorized:
            # Without active schedule, honor administrator manual disallow/disconnect
            decision = "quarantine"
        else:
            decision = get_access_decision(
                device.device_type,
                device.approval_status,
            )

    # ---------------------------------------------------------
    # Determine enforcement action and apply live firewall rules.
    # ---------------------------------------------------------

    active_driver = get_active_firewall_driver(db)
    firewall_result = None

    if decision == "allowed":
        action = "allow"
        enforcement_status = "allowed"

        message = (
            f"Internet access allowed for device "
            f"{device.ip_address} "
            f"({device.mac_address}) "
            f"on VLAN {device.vlan_id}"
        )

        status_changed = (old_enforcement_status != enforcement_status)
        if (force or status_changed) and device.ip_address:
            try:
                dev_iface = getattr(device, "network_interface", None)
                restore_device_l2(
                    device.ip_address,
                    device.mac_address,
                    interface=dev_iface if isinstance(dev_iface, str) else None,
                )
            except Exception:
                pass
            if active_driver.vendor != "sophos" and active_driver.is_configured():
                try:
                    firewall_result = active_driver.allow_device(device.ip_address, device.mac_address)
                    if firewall_result.get("status") == "allowed":
                        message += f" [{active_driver.vendor_title}: Unblocked]"
                except Exception as exc:
                    message += f" [{active_driver.vendor_title} Warning: {exc}]"
            elif is_sophos_configured():
                try:
                    firewall_result = sophos_allow_device(device.ip_address)
                    if firewall_result.get("status") == "allowed":
                        message += " [Sophos Firewall: Unblocked]"
                except Exception as exc:
                    message += f" [Sophos Warning: {exc}]"

    else:
        if decision == "isolated":
            action = "isolate"
            enforcement_status = "isolated"
        else:
            action = "quarantine"
            enforcement_status = "quarantined"

        message = (
            f"Internet access blocked for device "
            f"{device.ip_address} "
            f"({device.mac_address}) "
            f"on VLAN {device.vlan_id}"
        )

        status_changed = (old_enforcement_status != enforcement_status)
        if (force or status_changed) and device.ip_address:
            try:
                dev_iface = getattr(device, "network_interface", None)
                quarantine_device_l2(
                    device.ip_address,
                    device.mac_address,
                    burst=3,
                    interface=dev_iface if isinstance(dev_iface, str) else None,
                )
            except Exception:
                pass
            if active_driver.vendor != "sophos" and active_driver.is_configured():
                try:
                    firewall_result = active_driver.block_device(device.ip_address, device.hostname, device.mac_address)
                    if firewall_result.get("status") == "blocked":
                        message += f" [{active_driver.vendor_title}: Blocked & Disconnected]"
                    elif firewall_result.get("status") == "protected":
                        message += f" [{active_driver.vendor_title}: Protected Host]"
                except Exception as exc:
                    message += f" [{active_driver.vendor_title} Warning: {exc}]"
            elif is_sophos_configured():
                try:
                    firewall_result = sophos_block_device(device.ip_address, device.hostname)
                    if firewall_result.get("status") == "blocked":
                        message += " [Sophos Firewall: Blocked & Disconnected]"
                    elif firewall_result.get("status") == "protected":
                        message += " [Sophos: Protected Host]"
                except Exception as exc:
                    message += f" [Sophos Warning: {exc}]"

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

    is_live = (active_driver.is_configured() and active_driver.vendor != "simulation")
    is_live_sophos = is_sophos_configured() and (active_driver.vendor == "sophos" or not is_live)
    mode = "live_sophos" if is_live_sophos else (f"live_{active_driver.vendor}" if is_live else "simulation")

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
        "mode": mode,
        "firewall_vendor": "sophos" if is_live_sophos else active_driver.vendor,
        "firewall_result": firewall_result,
        "sophos_result": firewall_result,
    }
