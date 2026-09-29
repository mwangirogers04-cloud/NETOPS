VLAN_POLICY = {
    "computer": 20,
    "cctv": 30,
    "printer": 40,
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

