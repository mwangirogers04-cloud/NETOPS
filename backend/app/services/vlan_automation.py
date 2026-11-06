from sqlalchemy.orm import Session

from ..models.device import Device
from .device_classifier import classify_device
from .event_service import create_event
from .vlan_policy import get_vlan_for_device_type
from .switch_mapping import identify_switch_port


def automate_vlan_assignment(
    device: Device,
    db: Session,
) -> dict:
    """
    Automate VLAN assignment for a network device based on detected
    MAC address, vendor OUI, and hostname.

    Current mode:
        simulation

    Workflow:
        1. Classify device type using vendor, MAC, and hostname.
        2. Determine the VLAN from the central VLAN policy.
        3. Identify the switch connected to the device.
        4. Identify the switch port.
        5. Simulate VLAN configuration.
        6. Simulate VLAN verification.
        7. Store switch/port information on the device.
        8. Record audit events.
        9. Return the complete automation result.
    """

    # =========================================================
    # 1. Determine Device Type and VLAN from Vendor / MAC
    # =========================================================

    valid_types = {"ip_phone", "phone", "voip", "computer", "cctv", "printer", "server", "access_point"}
    if not device.device_type or device.device_type == "unknown" or device.device_type not in valid_types:
        classified_type = classify_device(
            hostname=device.hostname,
            vendor=device.vendor,
            mac_address=device.mac_address,
        )

        if classified_type != "unknown":
            device.device_type = classified_type
        elif not device.device_type or device.device_type == "unknown":
            # If device has an active IP on the LAN/WLAN, default to standard workstation (VLAN 20)
            device.device_type = "computer"

    vlan_id = get_vlan_for_device_type(
        device.device_type
    )

    device.vlan_id = vlan_id

    create_event(
        db,
        "vlan_automation",
        (
            f"VLAN automation auto-assigned VLAN {vlan_id} for device "
            f"{device.hostname or device.ip_address or device.mac_address} "
            f"({device.mac_address}) based on vendor '{device.vendor or 'Generic'}' "
            f"and device type '{device.device_type}'."
        ),
        device.id,
    )

    # =========================================================
    # 2. Identify switch and port
    # =========================================================

    switch_result = identify_switch_port(device)

    switch_name = switch_result.get("switch_name")
    switch_port = switch_result.get("switch_port")

    if switch_result.get("identified"):

        switch_status = "identified"
        port_status = "identified"

        device.switch_name = switch_name
        device.switch_port = switch_port

        create_event(
            db,
            "vlan_automation",
            (
                f"Switch identified for device "
                f"{device.ip_address}: "
                f"{switch_name}"
            ),
            device.id,
        )

        create_event(
            db,
            "vlan_automation",
            (
                f"Switch port identified for device "
                f"{device.ip_address}: "
                f"{switch_name} {switch_port}"
            ),
            device.id,
        )

    else:

        switch_status = "not_identified"
        port_status = "not_identified"

        create_event(
            db,
            "vlan_automation",
            (
                f"Switch not identified for device "
                f"{device.ip_address} "
                f"({device.mac_address}). "
                f"Reason: "
                f"{switch_result.get('reason', 'unknown')}"
            ),
            device.id,
        )

        create_event(
            db,
            "vlan_automation",
            (
                f"Switch port not identified for device "
                f"{device.ip_address} "
                f"({device.mac_address})"
            ),
            device.id,
        )

    # =========================================================
    # 3. Validate switch/port information
    # =========================================================

    if not switch_name or not switch_port:

        configuration_status = "waiting_for_switch_port"
        verification_status = "not_verified"
        action = "assign_vlan"

        create_event(
            db,
            "vlan_automation",
            (
                f"VLAN {vlan_id} determined for device "
                f"{device.ip_address} "
                f"({device.mac_address}), "
                f"but switch/port information is incomplete. "
                f"Configuration cannot proceed."
            ),
            device.id,
        )

        create_event(
            db,
            "vlan_automation",
            (
                f"VLAN verification pending for device "
                f"{device.ip_address} "
                f"because switch/port information "
                f"is incomplete"
            ),
            device.id,
        )


        return {
            "device_id": device.id,
            "ip_address": device.ip_address,
            "mac_address": device.mac_address,
            "device_type": device.device_type,
            "vlan_id": vlan_id,
            "switch_name": switch_name,
            "switch_port": switch_port,
            "switch_status": switch_status,
            "port_status": port_status,
            "action": action,
            "configuration_status": configuration_status,
            "verification_status": verification_status,
            "mode": "simulation",
        }

    # =========================================================
    # 4. Simulate VLAN configuration
    # =========================================================

    action = "assign_vlan"

    configuration_status = "simulated"

    create_event(
        db,
        "vlan_automation",
        (
            f"SIMULATION: configure switch "
            f"{switch_name} port {switch_port} "
            f"for device {device.ip_address} "
            f"({device.mac_address}) "
            f"to VLAN {vlan_id}"
        ),
        device.id,
    )

    # =========================================================
    # 5. Simulate VLAN verification
    # =========================================================

    verification_status = "verified_simulation"

    create_event(
        db,
        "vlan_automation",
        (
            f"SIMULATION VERIFIED: device "
            f"{device.ip_address} "
            f"({device.mac_address}) "
            f"would be assigned to VLAN {vlan_id} "
            f"on {switch_name} port {switch_port}"
        ),
        device.id,
    )

    # =========================================================
    # 6. Record successful completion
    # =========================================================

    create_event(
        db,
        "vlan_automation",
        (
            f"VLAN automation completed successfully for "
            f"device {device.ip_address} "
            f"({device.mac_address}): "
            f"VLAN {vlan_id}, "
            f"switch {switch_name}, "
            f"port {switch_port}"
        ),
        device.id,
    )

    # =========================================================
    # 7. Commit database changes
    # =========================================================


    # =========================================================
    # 8. Return complete automation result
    # =========================================================

    return {
        "device_id": device.id,
        "ip_address": device.ip_address,
        "mac_address": device.mac_address,
        "device_type": device.device_type,
        "vlan_id": vlan_id,
        "switch_name": switch_name,
        "switch_port": switch_port,
        "switch_status": switch_status,
        "port_status": port_status,
        "action": action,
        "configuration_status": configuration_status,
        "verification_status": verification_status,
        "mode": "simulation",
    }
