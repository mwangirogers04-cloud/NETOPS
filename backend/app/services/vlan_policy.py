VLAN_POLICY = {
    "ip_phone": 10,
    "phone": 10,
    "voip": 10,
    "computer": 20,
    "cctv": 30,
    "printer": 40,
    "server": 50,
    "access_point": 60,
    "ap": 60,
    "wifi_ap": 60,
    "unknown": 90,
}

VLAN_TO_DEVICE_TYPE = {
    10: "ip_phone",
    20: "computer",
    30: "cctv",
    40: "printer",
    50: "server",
    60: "access_point",
    90: "unknown",
}


def get_vlan_for_device_type(device_type: str | None) -> int:
    """
    Return the VLAN ID assigned to a device type.

    Unknown or unsupported device types are placed
    in the quarantine VLAN.
    """

    if not device_type:
        return VLAN_POLICY["unknown"]

    device_type = device_type.lower().strip()

    return VLAN_POLICY.get(
        device_type,
        VLAN_POLICY["unknown"],
    )


def get_device_type_for_vlan(vlan_id: int | None) -> str:
    """Return the canonical device type for a given VLAN ID."""
    if not vlan_id:
        return "unknown"
    try:
        return VLAN_TO_DEVICE_TYPE.get(int(vlan_id), "unknown")
    except (ValueError, TypeError):
        return "unknown"


def is_type_and_vlan_matching(device_type: str | None, vlan_id: int | None) -> bool:
    """
    Check if a device's TYPE and assigned VLAN section match identically.
    Rule: For a device to be connected it must be same in TYPE and VLAN section.
    """
    expected_vlan = get_vlan_for_device_type(device_type)
    try:
        current_vlan = int(vlan_id) if vlan_id is not None else 90
    except (ValueError, TypeError):
        current_vlan = 90
    return current_vlan == expected_vlan

