from unittest.mock import MagicMock, patch
from datetime import datetime, timezone
import pytest

from backend.app.models.device import Device
from backend.app.models.endpoint_update import EndpointUpdate
from backend.app.services.network_patch_scanner import (
    get_default_network,
    check_local_updates,
    probe_remote_network_host,
    assess_and_record_device_updates,
    scan_lan_for_updates,
)


def test_get_default_network_fallback():
    with patch("backend.app.services.network_patch_scanner.subprocess.run", side_effect=Exception("error")):
        net = get_default_network()
        assert net == "192.168.0.0/24"


def test_check_local_updates_parses_apt():
    mock_res = MagicMock()
    mock_res.stdout = "Listing...\nlinux-image-generic/noble-updates 6.8.0-31.31 amd64 [upgradable from: 6.8.0-22.22]\n"
    with patch("backend.app.services.network_patch_scanner.subprocess.run", return_value=mock_res):
        info = check_local_updates()
        assert info["operating_system"] == "Linux"
        assert info["update_status"] == "updates_available"
        assert info["pending_updates"] == 1


def test_check_local_updates_up_to_date():
    mock_res = MagicMock()
    mock_res.stdout = "Listing...\n"
    with patch("backend.app.services.network_patch_scanner.subprocess.run", return_value=mock_res):
        info = check_local_updates()
        assert info["update_status"] == "up_to_date"
        assert info["pending_updates"] == 0


def test_probe_remote_network_host_fingerprints_windows():
    probe = probe_remote_network_host(
        ip="192.168.0.102",
        vendor="Intel Corporate",
        hostname="DESKTOP-TEST",
    )
    assert probe["operating_system"] == "Windows"
    assert probe["hostname"] == "DESKTOP-TEST"


def test_assess_and_record_device_updates_for_local():
    db = MagicMock()
    device = Device(
        id=1,
        ip_address="192.168.0.101",
        mac_address="AA:BB:CC:DD:EE:01",
        hostname="kali",
        status="online",
    )
    with patch("backend.app.services.network_patch_scanner.check_local_updates", return_value={
        "operating_system": "Linux",
        "os_version": "6.0",
        "architecture": "x86_64",
        "update_status": "updates_available",
        "pending_updates": 5,
        "security_updates": None,
    }):
        res = assess_and_record_device_updates(
            device=device,
            db=db,
            local_ip="192.168.0.101",
            local_mac="AA:BB:CC:DD:EE:01",
        )
        assert res["update_status"] == "updates_available"
        assert res["pending_updates"] == 5
        db.add.assert_called_once()


def test_scan_lan_for_updates_workflow():
    db = MagicMock()
    dev1 = Device(
        id=1,
        ip_address="192.168.0.101",
        mac_address="AA:BB:CC:DD:EE:01",
        hostname="kali",
        status="online",
        device_type="computer",
    )
    dev2 = Device(
        id=2,
        ip_address="192.168.0.102",
        mac_address="AA:BB:CC:DD:EE:02",
        hostname="DESKTOP-REMOTE",
        status="online",
        device_type="computer",
    )

    with (
        patch("backend.app.services.network_patch_scanner.discover_devices", return_value=[]),
        patch("backend.app.services.network_patch_scanner.save_discovered_devices", return_value=[dev1, dev2]),
        patch("backend.app.services.network_patch_scanner.get_local_ip", return_value="192.168.0.101"),
        patch("backend.app.services.network_patch_scanner.get_local_mac", return_value="AA:BB:CC:DD:EE:01"),
        patch("backend.app.services.network_patch_scanner.assess_and_record_device_updates") as mock_assess,
        patch("backend.app.services.network_patch_scanner.create_event"),
    ):
        mock_assess.side_effect = [
            {"update_status": "updates_available"},
            {"update_status": "up_to_date"},
        ]
        result = scan_lan_for_updates("192.168.0.0/24", db)
        assert result["status"] == "completed"
        assert result["updates_available_count"] == 1
        assert result["up_to_date_count"] == 1
        assert result["machines_assessed"] == 2


def test_scan_lan_for_updates_strictly_scopes_online_and_network():
    db = MagicMock()
    # 1. Online device on target subnet 192.168.0.0/24
    dev_online_target = Device(
        id=10,
        ip_address="192.168.0.50",
        mac_address="AA:BB:CC:DD:EE:10",
        hostname="ONLINE-HOME-PC",
        status="online",
        network_name="Home Network",
    )
    # 2. Offline device on target subnet 192.168.0.0/24 (MUST BE EXCLUDED)
    dev_offline_target = Device(
        id=20,
        ip_address="192.168.0.60",
        mac_address="AA:BB:CC:DD:EE:20",
        hostname="OFFLINE-HOME-PC",
        status="offline",
        network_name="Home Network",
    )
    # 3. Online device on completely different subnet 192.168.88.0/24 (MUST BE EXCLUDED)
    dev_online_other = Device(
        id=30,
        ip_address="192.168.88.70",
        mac_address="AA:BB:CC:DD:EE:30",
        hostname="ONLINE-OFFICE-PC",
        status="online",
        network_name="Office Network",
    )

    # db.scalars().all() returns all candidate devices
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = [dev_online_target, dev_offline_target, dev_online_other]
    db.scalars.return_value = mock_scalars

    with (
        patch("backend.app.services.network_patch_scanner.discover_devices", return_value=[]),
        patch("backend.app.services.network_patch_scanner.save_discovered_devices", return_value=[]),
        patch("backend.app.services.network_patch_scanner.get_local_ip", return_value="192.168.0.50"),
        patch("backend.app.services.network_patch_scanner.get_local_mac", return_value="AA:BB:CC:DD:EE:10"),
        patch("backend.app.services.network_patch_scanner.assess_and_record_device_updates") as mock_assess,
        patch("backend.app.services.network_patch_scanner.create_event"),
    ):
        mock_assess.return_value = {
            "device_id": 10,
            "hostname": "ONLINE-HOME-PC",
            "update_status": "up_to_date",
            "pending_updates": 0,
        }

        result = scan_lan_for_updates("192.168.0.0/24", db, network_name="Home Network")
        assert result["status"] == "completed"
        # Only 1 device (dev_online_target) must have been assessed!
        assert result["machines_assessed"] == 1
        assert len(result["devices"]) == 1
        assert result["devices"][0]["device_id"] == 10
        mock_assess.assert_called_once_with(
            device=dev_online_target,
            db=db,
            local_ip="192.168.0.50",
            local_mac="AA:BB:CC:DD:EE:10",
        )
