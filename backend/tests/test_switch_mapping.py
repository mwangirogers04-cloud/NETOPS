
from types import SimpleNamespace

from backend.app.services.switch_mapping import (
    identify_switch_port_from_mac_table,
)


def make_device(mac_address):
    return SimpleNamespace(mac_address=mac_address)


def make_entry(vlan_id=30, interface="Gi0/7"):
    return {
        "vlan_id": vlan_id,
        "mac_address": "A4:4E:31:AD:0E:28",
        "interface": interface,
        "entry_type": "DYNAMIC",
    }


def test_identifies_matching_device():
    result = identify_switch_port_from_mac_table(
        make_device("A4:4E:31:AD:0E:28"),
        [make_entry()],
        "TEST-SWITCH",
    )

    assert result["identified"] is True
    assert result["switch_name"] == "TEST-SWITCH"
    assert result["switch_port"] == "Gi0/7"
    assert result["vlan_id"] == 30


def test_rejects_missing_device_mac():
    result = identify_switch_port_from_mac_table(
        make_device(None),
        [make_entry()],
        "TEST-SWITCH",
    )

    assert result["identified"] is False
    assert result["switch_port"] is None


def test_rejects_mac_not_found():
    result = identify_switch_port_from_mac_table(
        make_device("00:11:22:33:44:55"),
        [make_entry()],
        "TEST-SWITCH",
    )

    assert result["identified"] is False
    assert result["switch_port"] is None


def test_rejects_conflicting_interfaces():
    table = [
        make_entry(interface="Gi0/7"),
        make_entry(interface="Gi0/8"),
    ]

    result = identify_switch_port_from_mac_table(
        make_device("A4:4E:31:AD:0E:28"),
        table,
        "TEST-SWITCH",
    )

    assert result["identified"] is False
    assert result["switch_port"] is None


def test_rejects_conflicting_vlans():
    table = [
        make_entry(vlan_id=30),
        make_entry(vlan_id=40),
    ]

    result = identify_switch_port_from_mac_table(
        make_device("A4:4E:31:AD:0E:28"),
        table,
        "TEST-SWITCH",
    )

    assert result["identified"] is False
    assert result["switch_port"] is None
