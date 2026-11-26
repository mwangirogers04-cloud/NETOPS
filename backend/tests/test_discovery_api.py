import os
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend.app.api import discovery
from backend.app.main import app

client = TestClient(app)

def test_invalid_network_returns_bad_request(monkeypatch):
    monkeypatch.setattr(
        discovery,
        "discover_devices",
        MagicMock(side_effect=ValueError("Invalid network")),
    )

    with pytest.raises(HTTPException) as exc_info:
        discovery.run_discovery_scan(
            discovery.DiscoveryRequest(network="invalid"),
            db=MagicMock(),
        )

    # This test will pass after the API handles invalid
    # network input as HTTP 400 instead of HTTP 500.
    assert exc_info.value.status_code == 400

def test_unexpected_error_hides_internal_details(monkeypatch):
    monkeypatch.setattr(
        discovery,
        "discover_devices",
        MagicMock(
            side_effect=RuntimeError(
                "Sensitive database connection details"
            )
        ),
    )

    with pytest.raises(HTTPException) as exc_info:
        discovery.run_discovery_scan(
            discovery.DiscoveryRequest(
                network="192.168.1.0/24"
            ),
            db=MagicMock(),
        )

    assert exc_info.value.status_code == 500
    assert exc_info.value.detail == (
        "Discovery scan failed due to an internal error."
    )
    assert "Sensitive database connection details" not in (
        exc_info.value.detail
    )

def test_successful_discovery_returns_expected_response(monkeypatch):
    discovered = [
        {
            "ip_address": "192.168.1.10",
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "hostname": "TEST-PC",
            "vendor": "Dell",
        }
    ]

    saved_device = MagicMock()
    saved_device.id = 1
    saved_device.ip_address = "192.168.1.10"
    saved_device.mac_address = "AA:BB:CC:DD:EE:FF"
    saved_device.hostname = "TEST-PC"
    saved_device.vendor = "Dell"
    saved_device.device_type = "computer"
    saved_device.classification_status = "classified"
    saved_device.vlan_id = 20
    saved_device.approval_status = "pending"
    saved_device.status = "online"

    monkeypatch.setattr(
        discovery, "discover_devices", lambda network: discovered
    )
    save_mock = MagicMock(return_value=[saved_device])
    monkeypatch.setattr(
        discovery, "save_discovered_devices", save_mock
    )

    result = discovery.run_discovery_scan(
        discovery.DiscoveryRequest(network="192.168.1.0/24"),
        db=MagicMock(),
    )

    assert result["status"] == "completed"
    assert result["network"] == "192.168.1.0/24"
    assert result["devices_discovered"] == 1
    assert result["devices_processed"] == 1
    assert result["devices"][0]["hostname"] == "TEST-PC"
    assert result["devices"][0]["vlan_id"] == 20
    save_mock.assert_called_once()

@pytest.mark.parametrize("network", ["", "   ", "\t"])
def test_discovery_request_rejects_blank_network(network):
    with pytest.raises(Exception):
        discovery.DiscoveryRequest(network=network)

def test_http_scan_rejects_blank_network(monkeypatch):
    discover_mock = MagicMock()
    monkeypatch.setattr(
        discovery,
        "discover_devices",
        discover_mock,
    )

    response = client.post(
        "/discovery/scan",
        json={"network": "   "},
    )

    assert response.status_code == 422
    discover_mock.assert_not_called()

def test_http_scan_hides_internal_error_details(monkeypatch):
    monkeypatch.setattr(
        discovery,
        "discover_devices",
        MagicMock(
            side_effect=RuntimeError(
                "Sensitive database connection details"
            )
        ),
    )

    response = client.post(
        "/discovery/scan",
        json={"network": "192.168.1.0/24"},
    )

    assert response.status_code == 500
    assert response.json()["detail"] == (
        "Discovery scan failed due to an internal error."
    )
    assert (
        "Sensitive database connection details"
        not in response.text
    )

def test_http_scan_returns_successful_response(monkeypatch):
    discovered = [
        {
            "ip_address": "192.168.1.10",
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "hostname": "TEST-PC",
            "vendor": "Dell",
        }
    ]

    saved_device = MagicMock()
    saved_device.id = 1
    saved_device.ip_address = "192.168.1.10"
    saved_device.mac_address = "AA:BB:CC:DD:EE:FF"
    saved_device.hostname = "TEST-PC"
    saved_device.vendor = "Dell"
    saved_device.device_type = "computer"
    saved_device.classification_status = "classified"
    saved_device.vlan_id = 20
    saved_device.approval_status = "pending"
    saved_device.status = "online"

    discover_mock = MagicMock(return_value=discovered)
    save_mock = MagicMock(return_value=[saved_device])

    monkeypatch.setattr(
        discovery, "discover_devices", discover_mock
    )
    monkeypatch.setattr(
        discovery, "save_discovered_devices", save_mock
    )

    response = client.post(
        "/discovery/scan",
        json={"network": "192.168.1.0/24"},
    )

    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "completed"
    assert data["network"] == "192.168.1.0/24"
    assert data["devices_discovered"] == 1
    assert data["devices_processed"] == 1
    assert data["devices"][0]["hostname"] == "TEST-PC"
    assert data["devices"][0]["vlan_id"] == 20

    discover_mock.assert_called_once_with("192.168.1.0/24")
    save_mock.assert_called_once()


def test_http_scan_with_wlan0_interface(monkeypatch):
    discovered = [
        {
            "ip_address": "192.168.0.105",
            "mac_address": "11:22:33:44:55:66",
            "interface": "wlan0",
            "medium": "wireless",
            "hostname": "WIFI-LAPTOP",
            "vendor": "Intel",
        }
    ]

    saved_device = MagicMock()
    saved_device.id = 2
    saved_device.ip_address = "192.168.0.105"
    saved_device.mac_address = "11:22:33:44:55:66"
    saved_device.hostname = "WIFI-LAPTOP"
    saved_device.vendor = "Intel"
    saved_device.device_type = "computer"
    saved_device.classification_status = "normal"
    saved_device.vlan_id = 20
    saved_device.approval_status = "pending"
    saved_device.status = "online"

    discover_mock = MagicMock(return_value=discovered)
    save_mock = MagicMock(return_value=[saved_device])

    monkeypatch.setattr(discovery, "discover_devices", discover_mock)
    monkeypatch.setattr(discovery, "save_discovered_devices", save_mock)

    response = client.post(
        "/discovery/scan",
        json={"network": "192.168.0.0/24", "interface": "wlan0"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["interface"] == "wlan0"
    assert data["devices_discovered"] == 1
    discover_mock.assert_called_once_with("192.168.0.0/24", interface="wlan0")
    save_mock.assert_called_once()


def test_http_scan_detects_duplicate_ip_conflicts(monkeypatch):
    dev1 = MagicMock()
    dev1.id = 10
    dev1.ip_address = "192.168.0.55"
    dev1.mac_address = "AA:11:22:33:44:55"
    dev1.hostname = "DEVICE-A"
    dev1.vendor = "VendorA"
    dev1.device_type = "computer"
    dev1.classification_status = "normal"
    dev1.vlan_id = 20
    dev1.approval_status = "approved"
    dev1.status = "online"

    dev2 = MagicMock()
    dev2.id = 11
    dev2.ip_address = "192.168.0.55"
    dev2.mac_address = "BB:11:22:33:44:55"
    dev2.hostname = "DEVICE-B"
    dev2.vendor = "VendorB"
    dev2.device_type = "phone"
    dev2.classification_status = "normal"
    dev2.vlan_id = 20
    dev2.approval_status = "approved"
    dev2.status = "online"

    monkeypatch.setattr(discovery, "discover_devices", MagicMock(return_value=[]))
    monkeypatch.setattr(discovery, "save_discovered_devices", MagicMock(return_value=[dev1, dev2]))

    response = client.post(
        "/discovery/scan",
        json={"network": "192.168.0.0/24", "interface": "wlan0"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["ip_conflicts_count"] == 1
    assert len(data["duplicate_ips"]) == 1
    assert data["duplicate_ips"][0]["ip_address"] == "192.168.0.55"
    assert data["duplicate_ips"][0]["count"] == 2


def test_http_scan_unreachable_network_returns_informative_status(monkeypatch):
    monkeypatch.setattr(discovery, "discover_devices", MagicMock(return_value=[]))
    monkeypatch.setattr(
        discovery,
        "detect_local_subnets",
        MagicMock(
            return_value={
                "interfaces": [
                    {"interface": "eth0", "ip": "192.168.0.111", "network": "192.168.0.0/24"}
                ],
                "default_network": "192.168.0.0/24",
            }
        ),
    )
    orig_exists = os.path.exists
    monkeypatch.setattr("os.path.exists", lambda path: True if "sys/class/net" in str(path) else orig_exists(path))

    # Disable mock/test bypass flag inside run_discovery_scan to test bare-metal physical host behavior
    with monkeypatch.context() as m:
        m.setenv("PYTEST_CURRENT_TEST", "")
        response = client.post(
            "/discovery/scan",
            json={"network": "10.50.0.0/24", "network_name": "Branch Office"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "unreachable_network"
        assert "cannot be directly reached" in data["message"]
        assert data["devices_discovered"] == 0
        assert "probe_command" in data
        assert "10.50.0.0/24" in data["probe_command"]


def test_cloud_scan_when_empty_returns_waiting_for_agent_and_no_fake_devices(monkeypatch):
    monkeypatch.setattr(discovery, "discover_devices", MagicMock(return_value=[]))
    orig_exists = os.path.exists
    monkeypatch.setattr("os.path.exists", lambda path: False if "sys/class/net" in str(path) else orig_exists(path))
    monkeypatch.setenv("CLOUD_MODE", "true")

    response = client.post(
        "/discovery/scan",
        json={"network": "192.168.0.0/24", "network_name": "NonExistentSiteXYZ"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "waiting_for_agent"
    assert data["devices_discovered"] == 0
    assert len(data["devices"]) == 0
    assert "probe_command" in data


def test_get_local_subnets_auto_detects_client_ip_param():
    response = client.get("/discovery/local-subnets?client_ip=192.168.88.100")
    assert response.status_code == 200
    data = response.json()
    assert data["default_network"] == "192.168.88.0/24"
    assert data["client_ip"] == "192.168.88.100"
    assert data["client_network"] == "192.168.88.0/24"


def test_get_local_subnets_auto_detects_forwarded_client_ip():
    response = client.get(
        "/discovery/local-subnets",
        headers={"X-Forwarded-For": "192.168.88.100, 10.0.0.1"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["default_network"] == "192.168.88.0/24"
    assert data["client_ip"] == "192.168.88.100"
    assert data["client_network"] == "192.168.88.0/24"





