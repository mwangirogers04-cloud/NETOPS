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

