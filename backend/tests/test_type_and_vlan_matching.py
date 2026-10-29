import pytest
from types import SimpleNamespace
from backend.app.services.vlan_policy import (
    get_vlan_for_device_type,
    get_device_type_for_vlan,
    is_type_and_vlan_matching,
)
from backend.app.services.access_policy import (
    get_access_decision,
    get_access_reason,
)


def test_vlan_type_mappings():
    assert get_vlan_for_device_type("ip_phone") == 10
    assert get_vlan_for_device_type("computer") == 20
    assert get_vlan_for_device_type("cctv") == 30
    assert get_vlan_for_device_type("printer") == 40
    assert get_vlan_for_device_type("server") == 50
    assert get_vlan_for_device_type("access_point") == 60
    assert get_vlan_for_device_type("unknown") == 90

    assert get_device_type_for_vlan(10) == "ip_phone"
    assert get_device_type_for_vlan(20) == "computer"
    assert get_device_type_for_vlan(30) == "cctv"
    assert get_device_type_for_vlan(40) == "printer"
    assert get_device_type_for_vlan(50) == "server"
    assert get_device_type_for_vlan(60) == "access_point"
    assert get_device_type_for_vlan(90) == "unknown"


def test_is_type_and_vlan_matching():
    # Matching pairs
    assert is_type_and_vlan_matching("computer", 20) is True
    assert is_type_and_vlan_matching("ip_phone", 10) is True
    assert is_type_and_vlan_matching("cctv", 30) is True
    assert is_type_and_vlan_matching("printer", 40) is True
    assert is_type_and_vlan_matching("server", 50) is True
    assert is_type_and_vlan_matching("access_point", 60) is True
    assert is_type_and_vlan_matching("unknown", 90) is True

    # Mismatched pairs
    assert is_type_and_vlan_matching("computer", 10) is False
    assert is_type_and_vlan_matching("computer", 30) is False
    assert is_type_and_vlan_matching("computer", 90) is False
    assert is_type_and_vlan_matching("cctv", 20) is False
    assert is_type_and_vlan_matching("printer", 20) is False
    assert is_type_and_vlan_matching("ip_phone", 20) is False


def test_access_decision_requires_matching_type_and_vlan():
    # When TYPE and VLAN match: allowed
    assert get_access_decision(
        device_type="computer",
        approval_status="approved",
        vlan_id=20,
    ) == "allowed"

    assert get_access_decision(
        device_type="cctv",
        approval_status="approved",
        vlan_id=30,
    ) == "allowed"

    # When TYPE and VLAN mismatch: quarantined
    assert get_access_decision(
        device_type="computer",
        approval_status="approved",
        vlan_id=30,
    ) == "quarantine"

    assert get_access_decision(
        device_type="cctv",
        approval_status="approved",
        vlan_id=20,
    ) == "quarantine"


def test_access_reason_explains_mismatch():
    reason = get_access_reason(
        device_type="computer",
        approval_status="approved",
        vlan_id=30,
    )
    assert "Type & VLAN mismatch" in reason
    assert "VLAN 20" in reason
