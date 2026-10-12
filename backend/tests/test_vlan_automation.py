from unittest.mock import MagicMock, patch
from datetime import datetime
from backend.app.models.device import Device
from backend.app.services.vlan_automation import (
    automate_vlan_assignment,
)


def make_device(mac_address):
    return Device(
        id=1,
        mac_address=mac_address,
        ip_address="192.168.0.50",
        hostname="TEST-PRINTER",
        device_type="printer",
    )


def test_vlan_assignment_with_known_switch_port(monkeypatch):
    db = MagicMock()
    device = make_device("AA:BB:CC:11:22:33")

    monkeypatch.setattr(
        "backend.app.services.vlan_automation.create_event",
        MagicMock(),
    )

    result = automate_vlan_assignment(device, db)

    assert result["vlan_id"] == 40
    assert result["switch_name"] == "ACCESS-SW01"
    assert result["switch_port"] == "Gi0/8"
    assert result["configuration_status"] == "simulated"
    assert result["verification_status"] == "verified_simulation"
    assert result["mode"] == "simulation"

    # The service must leave commits to its caller.
    db.commit.assert_not_called()
    db.refresh.assert_not_called()


def test_vlan_assignment_without_known_switch_port(monkeypatch):
    db = MagicMock()
    device = make_device("02:AA:BB:CC:DD:99")

    monkeypatch.setattr(
        "backend.app.services.vlan_automation.create_event",
        MagicMock(),
    )

    result = automate_vlan_assignment(device, db)

    assert result["vlan_id"] == 40
    assert result["switch_name"] is None
    assert result["switch_port"] is None
    assert result["configuration_status"] == "waiting_for_switch_port"
    assert result["verification_status"] == "not_verified"
    assert result["mode"] == "simulation"

    # The service must leave commits to its caller.
    db.commit.assert_not_called()
    db.refresh.assert_not_called()

def test_approval_commits_after_vlan_automation_and_keeps_quarantine(
    monkeypatch,
):
    from unittest.mock import MagicMock, call

    from fastapi.testclient import TestClient

    from backend.app.api import devices
    from backend.app.database import get_db
    from backend.app.main import app

    device = make_device("02:AA:BB:CC:DD:77")
    device.approval_status = "pending"
    device.enforcement_status = "quarantined"
    device.internet_access_authorized = False
    device.classification_status = "normal"
    device.status = "online"
    device.first_seen = datetime.now()
    device.last_seen = datetime.now()
    device.vendor = "Test"
    device.switch_name = None
    device.switch_port = None
    device.notes = None

    db = MagicMock()
    db.get.return_value = device

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db

    def fake_vlan_automation(target_device, session):
        assert target_device is device
        assert session is db
        assert target_device.approval_status == "approved"
        return {"mode": "simulation", "vlan_id": 40}

    monkeypatch.setattr(
        devices,
        "automate_vlan_assignment",
        fake_vlan_automation,
    )
    monkeypatch.setattr(
        devices,
        "create_event",
        MagicMock(),
    )

    try:
        with TestClient(app) as client:
            response = client.patch("/devices/1/approve")
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 200
    data = response.json()
    assert data["approval_status"] == "approved"
    assert data["enforcement_status"] == "quarantined"
    assert data["internet_access_authorized"] is False

    db.commit.assert_called_once()
    db.refresh.assert_called_once_with(device)
