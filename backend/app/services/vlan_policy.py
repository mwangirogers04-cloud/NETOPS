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

