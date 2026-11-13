import pytest
from unittest.mock import patch, MagicMock
from backend.app.models.device import Device
from backend.app.services.endpoint_health_monitor import reconcile_dual_interface_devices


def test_dual_interface_lan_active_forces_wlan_offline():
    dev_lan = Device(
        id=101,
        hostname="ROGERS-LAPTOP",
        mac_address="00:11:22:33:44:55",
        network_interface="eth0",
        status="online",
    )
    dev_wlan = Device(
        id=102,
        hostname="ROGERS-LAPTOP",
        mac_address="AA:BB:CC:DD:EE:FF",
        network_interface="wlan0",
        status="online",
    )
    devices = [dev_lan, dev_wlan]
    online = [dev_lan, dev_wlan]

    reconcile_dual_interface_devices(devices, online)

    assert dev_lan.status == "online"
    assert dev_wlan.status == "offline"
    assert dev_wlan not in online
    assert dev_lan in online


def test_dual_interface_wlan_active_forces_lan_offline():
    dev_lan = Device(
        id=101,
        hostname="WORKSTATION-01",
        mac_address="00:11:22:33:44:01",
        network_interface="eth0",
        status="offline",
    )
    dev_wlan = Device(
        id=102,
        hostname="WORKSTATION-01",
        mac_address="AA:BB:CC:DD:EE:02",
        network_interface="wlan0",
        status="online",
    )
    devices = [dev_lan, dev_wlan]
    online = [dev_wlan]

    reconcile_dual_interface_devices(devices, online)

    assert dev_lan.status == "offline"
    assert dev_wlan.status == "online"
    assert dev_wlan in online
    assert dev_lan not in online


def test_localhost_lan_carrier_up_forces_wlan_offline():
    dev_kali_eth = Device(
        id=339,
        hostname="kali",
        mac_address="B4:B6:86:8A:69:02",
        network_interface="eth0",
        status="online",
    )
    dev_kali_wlan = Device(
        id=349,
        hostname="kali",
        mac_address="D4:6D:6D:E6:A2:67",
        network_interface="wlan0",
        status="online",
    )
    devices = [dev_kali_eth, dev_kali_wlan]
    online = [dev_kali_eth, dev_kali_wlan]

    with patch("backend.app.services.endpoint_health_monitor.get_local_active_connection", return_value=("eth0", "wlan0")):
        reconcile_dual_interface_devices(devices, online)

    assert dev_kali_eth.status == "online"
    assert dev_kali_wlan.status == "offline"
    assert dev_kali_wlan not in online
    assert dev_kali_eth in online


def test_localhost_lan_carrier_down_forces_wlan_online():
    dev_kali_eth = Device(
        id=339,
        hostname="kali",
        mac_address="B4:B6:86:8A:69:02",
        network_interface="eth0",
        status="online",
    )
    dev_kali_wlan = Device(
        id=349,
        hostname="kali",
        mac_address="D4:6D:6D:E6:A2:67",
        network_interface="wlan0",
        status="offline",
    )
    devices = [dev_kali_eth, dev_kali_wlan]
    online = [dev_kali_eth]

    with patch("backend.app.services.endpoint_health_monitor.get_local_active_connection", return_value=("wlan0", "eth0")):
        reconcile_dual_interface_devices(devices, online)

    assert dev_kali_eth.status == "offline"
    assert dev_kali_wlan.status == "online"
    assert dev_kali_eth not in online
    assert dev_kali_wlan in online
