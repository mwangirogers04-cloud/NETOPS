from unittest.mock import MagicMock, patch

from backend.app.models.device import Device
from backend.app.services.switch_enforcement import (
    switch_quarantine_device,
    switch_restore_device,
    QUARANTINE_VLAN,
)


def test_switch_quarantine_device_vlan():
    dev = Device(
        id=1,
        ip_address="192.168.0.55",
        mac_address="AA:BB:CC:DD:EE:11",
        device_type="computer",
        switch_name="CORE-SW01",
        switch_port="Gi0/10",
    )
    mock_driver = MagicMock()
    mock_driver.set_port_vlan.return_value = {"success": True, "port": "Gi0/10", "vlan_id": 90}

    with patch("backend.app.services.switch_enforcement.get_active_switch_driver", return_value=mock_driver):
        res = switch_quarantine_device(dev, method="vlan")
        assert res["status"] == "quarantined"
        assert res["method"] == "vlan"
        assert res["vlan_id"] == QUARANTINE_VLAN
        assert res["switch_port"] == "Gi0/10"
        mock_driver.set_port_vlan.assert_called_with("Gi0/10", vlan_id=90, mode="access")


def test_switch_quarantine_device_shutdown():
    dev = Device(
        id=2,
        ip_address="192.168.0.56",
        mac_address="AA:BB:CC:DD:EE:12",
        device_type="computer",
        switch_name="ACCESS-SW01",
        switch_port="Gi0/5",
    )
    mock_driver = MagicMock()
    mock_driver.set_port_admin_state.return_value = {"success": True, "port": "Gi0/5", "admin_state": "down"}

    with patch("backend.app.services.switch_enforcement.get_active_switch_driver", return_value=mock_driver):
        res = switch_quarantine_device(dev, method="shutdown")
        assert res["status"] == "quarantined"
        assert res["method"] == "shutdown"
        assert res["switch_port"] == "Gi0/5"
        mock_driver.set_port_admin_state.assert_called_with("Gi0/5", enabled=False)


def test_switch_restore_device():
    dev = Device(
        id=3,
        ip_address="192.168.0.57",
        mac_address="AA:BB:CC:DD:EE:13",
        device_type="computer",
        switch_name="ACCESS-SW01",
        switch_port="Gi0/6",
        vlan_id=20,
    )
    mock_driver = MagicMock()
    mock_driver.set_port_vlan.return_value = {"success": True, "port": "Gi0/6", "vlan_id": 20}
    mock_driver.set_port_admin_state.return_value = {"success": True, "port": "Gi0/6", "admin_state": "up"}

    with patch("backend.app.services.switch_enforcement.get_active_switch_driver", return_value=mock_driver):
        res = switch_restore_device(dev, target_vlan=20)
        assert res["status"] == "allowed"
        assert res["vlan_id"] == 20
        mock_driver.set_port_admin_state.assert_called_with("Gi0/6", enabled=True)
        mock_driver.set_port_vlan.assert_called_with("Gi0/6", vlan_id=20, mode="access")


def test_switch_quarantine_unmapped_device():
    dev = Device(
        id=4,
        ip_address="192.168.0.99",
        mac_address="00:11:22:33:44:99",
        device_type="unknown",
        switch_name=None,
        switch_port=None,
    )
    with patch("backend.app.services.switch_enforcement.identify_switch_port", return_value={"identified": False}):
        res = switch_quarantine_device(dev)
        assert res["status"] == "skipped"
        assert "No physical switchport mapped" in res["reason"]
