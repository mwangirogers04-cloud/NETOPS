import logging
from typing import Any
from sqlalchemy.orm import Session

from ..models.device import Device
from .l2_quarantine import _is_cloud_host
from .switch.manager import get_active_switch_driver
from .switch_mapping import identify_switch_port
from .vlan_policy import get_vlan_for_device_type

logger = logging.getLogger(__name__)

QUARANTINE_VLAN = 90
QUARANTINE_VLAN_NAME = "NETOPS_QUARANTINE"


def switch_quarantine_device(
    device: Device,
    db: Session | None = None,
    method: str = "vlan",
) -> dict[str, Any]:
    """
    Enforce immediate Layer 2 / Layer 3 switch-level quarantine for a device.
    
    Methods:
      - 'vlan': Reassigns the device's physical switchport to Quarantine VLAN 90.
                Isolates the device in an unrouted broadcast domain with zero internet/LAN route.
      - 'shutdown': Physically disables the switchport (administrative shutdown).
    """
    if _is_cloud_host():
        return {
            "status": "quarantined",
            "method": method,
            "switch_port": getattr(device, "switch_port", None) or "Simulated",
            "switch_name": getattr(device, "switch_name", None) or "Cloud-Switch",
            "message": "Cloud host: switch port quarantine delegated to local network agent",
        }

    switch_name = device.switch_name
    switch_port = device.switch_port

    if not switch_port:
        try:
            mapping = identify_switch_port(device)
            if mapping.get("identified"):
                switch_name = mapping.get("switch_name")
                switch_port = mapping.get("switch_port")
                device.switch_name = switch_name
                device.switch_port = switch_port
        except Exception as map_err:
            logger.debug("Switch port lookup notice: %s", map_err)

    if not switch_port:
        return {
            "status": "skipped",
            "reason": f"No physical switchport mapped for device {device.ip_address} ({device.mac_address})",
        }

    try:
        driver = get_active_switch_driver(db)
        
        if method == "shutdown":
            res = driver.set_port_admin_state(switch_port, enabled=False)
            logger.info(
                "[SWITCH ENFORCEMENT] Port %s on switch '%s' shut down for device %s (%s)",
                switch_port, switch_name, device.ip_address, device.mac_address
            )
            return {
                "status": "quarantined",
                "method": "shutdown",
                "switch_name": switch_name,
                "switch_port": switch_port,
                "driver_result": res,
            }
        else:
            try:
                driver.create_vlan(QUARANTINE_VLAN, QUARANTINE_VLAN_NAME)
            except Exception:
                pass

            res = driver.set_port_vlan(switch_port, vlan_id=QUARANTINE_VLAN, mode="access")
            logger.info(
                "[SWITCH ENFORCEMENT] Port %s on switch '%s' moved to Quarantine VLAN %d for device %s (%s)",
                switch_port, switch_name, QUARANTINE_VLAN, device.ip_address, device.mac_address
            )
            return {
                "status": "quarantined",
                "method": "vlan",
                "vlan_id": QUARANTINE_VLAN,
                "switch_name": switch_name,
                "switch_port": switch_port,
                "driver_result": res,
            }

    except Exception as exc:
        logger.error("[SWITCH ENFORCEMENT ERROR] Failed switch quarantine on %s/%s: %s", switch_name, switch_port, exc)
        return {
            "status": "error",
            "error": str(exc),
            "switch_name": switch_name,
            "switch_port": switch_port,
        }


def switch_restore_device(
    device: Device,
    db: Session | None = None,
    target_vlan: int | None = None,
) -> dict[str, Any]:
    """
    Restore an allowed device's switchport to its authorized production VLAN
    and ensure the port is administratively enabled (no shutdown).
    """
    if _is_cloud_host():
        return {
            "status": "allowed",
            "vlan_id": target_vlan or getattr(device, "vlan_id", 20),
            "switch_port": getattr(device, "switch_port", None) or "Simulated",
            "switch_name": getattr(device, "switch_name", None) or "Cloud-Switch",
            "message": "Cloud host: switch port restoration delegated to local network agent",
        }

    switch_name = device.switch_name
    switch_port = device.switch_port

    if not switch_port:
        try:
            mapping = identify_switch_port(device)
            if mapping.get("identified"):
                switch_name = mapping.get("switch_name")
                switch_port = mapping.get("switch_port")
                device.switch_name = switch_name
                device.switch_port = switch_port
        except Exception as map_err:
            logger.debug("Switch port lookup notice: %s", map_err)

    if not switch_port:
        return {
            "status": "skipped",
            "reason": f"No physical switchport mapped for device {device.ip_address} ({device.mac_address})",
        }

    if not target_vlan or target_vlan == QUARANTINE_VLAN:
        target_vlan = get_vlan_for_device_type(device.device_type)
        if target_vlan == QUARANTINE_VLAN:
            target_vlan = 20

    try:
        driver = get_active_switch_driver(db)
        driver.set_port_admin_state(switch_port, enabled=True)
        res = driver.set_port_vlan(switch_port, vlan_id=target_vlan, mode="access")
        logger.info(
            "[SWITCH RESTORE] Port %s on switch '%s' restored to VLAN %d for device %s (%s)",
            switch_port, switch_name, target_vlan, device.ip_address, device.mac_address
        )
        return {
            "status": "allowed",
            "vlan_id": target_vlan,
            "switch_name": switch_name,
            "switch_port": switch_port,
            "driver_result": res,
        }

    except Exception as exc:
        logger.error("[SWITCH RESTORE ERROR] Failed switch restore on %s/%s: %s", switch_name, switch_port, exc)
        return {
            "status": "error",
            "error": str(exc),
            "switch_name": switch_name,
            "switch_port": switch_port,
        }
