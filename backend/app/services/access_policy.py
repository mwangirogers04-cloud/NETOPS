KNOWN_DEVICE_TYPES = {
    "ip_phone",
    "computer",
    "cctv",
    "printer",
    "server",
    "access_point",
}


def normalize_device_type(
    device_type: str | None,
) -> str | None:
    """
    Normalize a device type.

    Returns None when the device type is unknown,
    empty, or unsupported.
    """

    if not device_type:
        return None

    normalized = device_type.lower().strip()

    if normalized in ("phone", "voip", "ip_phone", "ipphone"):
        return "ip_phone"

    if normalized in ("server", "servers"):
        return "server"

    if normalized in ("access_point", "ap", "wap", "wifi_ap", "accesspoint"):
        return "access_point"

    if normalized not in KNOWN_DEVICE_TYPES:
        return None

    return normalized


def get_access_decision(
    device_type: str | None,
    approval_status: str,
    enforcement_status: str | None = None,
    vlan_id: int | None = None,
) -> str:
    """
    Determine the access decision.

    NETOPS access rules:

    1. Pending devices are quarantined.
    2. Rejected devices are quarantined.
    3. Unknown/unclassified devices are quarantined.
    4. Approved recognized devices are allowed IF TYPE and VLAN section match.
    5. enforcement_status is NOT used to calculate the
       approval-based access decision.

    Manual blocking is handled separately by the
    enforcement action.
    """

    normalized_type = normalize_device_type(
        device_type
    )

    if approval_status != "approved":
        return "quarantine"

    if normalized_type is None:
        return "quarantine"

    if vlan_id is not None:
        from .vlan_policy import is_type_and_vlan_matching
        if not is_type_and_vlan_matching(device_type, vlan_id):
            return "quarantine"

    return "allowed"


def get_access_reason(
    device_type: str | None,
    approval_status: str,
    vlan_id: int | None = None,
) -> str:
    """
    Explain why the device currently has its
    approval-based access decision.
    """

    normalized_type = normalize_device_type(
        device_type
    )

    if approval_status == "pending":
        return "Pending administrator approval"

    if approval_status == "rejected":
        return "Rejected by administrator"

    if normalized_type is None:
        return "Unknown or unrecognized device type"

    if vlan_id is not None:
        from .vlan_policy import is_type_and_vlan_matching, get_vlan_for_device_type
        if not is_type_and_vlan_matching(device_type, vlan_id):
            expected = get_vlan_for_device_type(device_type)
            return f"Type & VLAN mismatch: '{device_type or 'unknown'}' requires VLAN {expected}, but assigned VLAN {vlan_id}. For a device to be connected it must be same in TYPE and VLAN section."

    if approval_status == "approved":
        return "Approved recognized device with network access allowed"

    return "Network access restricted"
