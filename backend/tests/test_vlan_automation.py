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
        client = TestClient(app)
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


def test_set_device_vlan_to_90_quarantines_and_disconnects_internet(monkeypatch):
    from fastapi.testclient import TestClient
    from backend.app.api import devices
    from backend.app.database import get_db
    from backend.app.main import app

    device = make_device("02:AA:BB:CC:DD:88")
    device.approval_status = "approved"
    device.enforcement_status = "allowed"
    device.internet_access_authorized = True
    device.classification_status = "normal"
    device.status = "online"
    device.first_seen = datetime.now()
    device.last_seen = datetime.now()
    device.vlan_id = 20

    db = MagicMock()
    db.get.return_value = device

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db

    mock_enforce = MagicMock(return_value={"action": "quarantine"})
    monkeypatch.setattr(devices, "enforce_device_access", mock_enforce)
    monkeypatch.setattr(devices, "create_event", MagicMock())

    try:
        client = TestClient(app)
        response = client.patch("/devices/1/vlan", json={"vlan_id": 90})
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 200
    data = response.json()
    assert data["vlan_id"] == 90
    assert data["internet_access_authorized"] is False
    assert data["enforcement_status"] == "quarantined"
    mock_enforce.assert_called_once_with(device, db, force=True)


def test_set_device_type_unknown_quarantines_and_disconnects_internet(monkeypatch):
    from fastapi.testclient import TestClient
    from backend.app.api import devices
    from backend.app.database import get_db
    from backend.app.main import app

    device = make_device("02:AA:BB:CC:DD:89")
    device.approval_status = "approved"
    device.enforcement_status = "allowed"
    device.internet_access_authorized = True
    device.classification_status = "normal"
    device.status = "online"
    device.first_seen = datetime.now()
    device.last_seen = datetime.now()
    device.vlan_id = 20
    device.device_type = "computer"

    db = MagicMock()
    db.get.return_value = device

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db

    mock_enforce = MagicMock(return_value={"action": "quarantine"})
    monkeypatch.setattr(devices, "enforce_device_access", mock_enforce)
    monkeypatch.setattr(devices, "create_event", MagicMock())

    try:
        client = TestClient(app)
        response = client.patch("/devices/1/type", json={"device_type": "unknown"})
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 200
    data = response.json()
    assert data["vlan_id"] == 90
    assert data["device_type"] == "unknown"
    assert data["internet_access_authorized"] is False
    assert data["enforcement_status"] == "quarantined"
    mock_enforce.assert_called_once_with(device, db, force=True)


def test_allow_device_restores_operational_vlan_from_quarantine(monkeypatch):
    from fastapi.testclient import TestClient
    from backend.app.api import devices
    from backend.app.database import get_db
    from backend.app.main import app

    device = make_device("02:AA:BB:CC:DD:90")
    device.approval_status = "approved"
    device.enforcement_status = "quarantined"
    device.internet_access_authorized = False
    device.classification_status = "normal"
    device.status = "online"
    device.first_seen = datetime.now()
    device.last_seen = datetime.now()
    device.vlan_id = 90
    device.device_type = "computer"

    db = MagicMock()
    db.get.return_value = device

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db

    mock_enforce = MagicMock(return_value={"action": "allow"})
    monkeypatch.setattr(devices, "enforce_device_access", mock_enforce)
    monkeypatch.setattr(devices, "create_event", MagicMock())

    try:
        client = TestClient(app)
        response = client.post("/devices/1/allow")
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 200
    assert device.vlan_id == 20
    assert device.internet_access_authorized is True
    mock_enforce.assert_called_once_with(device, db, force=True)


def test_vlan_assignment_for_ip_phone(monkeypatch):
    db = MagicMock()
    device = make_device("02:AA:BB:CC:DD:88")
    device.device_type = "ip_phone"

    monkeypatch.setattr(
        "backend.app.services.vlan_automation.create_event",
        MagicMock(),
    )

    result = automate_vlan_assignment(device, db)
    assert result["vlan_id"] == 10
    assert device.vlan_id == 10


def test_set_device_vlan_to_10_ip_phone():
    from fastapi.testclient import TestClient
    from backend.app.database import get_db
    from backend.app.main import app

    device = make_device("02:AA:BB:CC:DD:10")
    device.vlan_id = 90
    device.approval_status = "approved"
    device.enforcement_status = "quarantined"
    device.internet_access_authorized = False
    device.classification_status = "normal"
    device.status = "online"
    device.first_seen = datetime.now()
    device.last_seen = datetime.now()

    db = MagicMock()
    db.get.return_value = device

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db

    try:
        client = TestClient(app)
        response = client.patch("/devices/1/vlan", json={"vlan_id": 10})
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 200
    assert device.vlan_id == 10


def test_set_device_type_to_ip_phone():
    from fastapi.testclient import TestClient
    from backend.app.database import get_db
    from backend.app.main import app

    device = make_device("02:AA:BB:CC:DD:11")
    device.device_type = "unknown"
    device.vlan_id = 90
    device.approval_status = "pending"
    device.enforcement_status = "quarantined"
    device.internet_access_authorized = False
    device.classification_status = "normal"
    device.status = "online"
    device.first_seen = datetime.now()
    device.last_seen = datetime.now()

    db = MagicMock()
    db.get.return_value = device

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db

    try:
        client = TestClient(app)
        response = client.patch("/devices/1/type", json={"device_type": "ip_phone"})
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 200
    assert device.device_type == "ip_phone"
    assert device.vlan_id == 10


def test_vlan_assignment_for_server_and_access_point(monkeypatch):
    db = MagicMock()
    monkeypatch.setattr(
        "backend.app.services.vlan_automation.create_event",
        MagicMock(),
    )

    device_server = make_device("02:AA:BB:CC:DD:50")
    device_server.device_type = "server"
    result_server = automate_vlan_assignment(device_server, db)
    assert result_server["vlan_id"] == 50
    assert device_server.vlan_id == 50

    device_ap = make_device("02:AA:BB:CC:DD:60")
    device_ap.device_type = "access_point"
    result_ap = automate_vlan_assignment(device_ap, db)
    assert result_ap["vlan_id"] == 60
    assert device_ap.vlan_id == 60


def test_set_device_vlan_to_50_and_60():
    from fastapi.testclient import TestClient
    from backend.app.database import get_db
    from backend.app.main import app

    device = make_device("02:AA:BB:CC:DD:55")
    device.vlan_id = 90
    device.approval_status = "approved"
    device.enforcement_status = "quarantined"
    device.internet_access_authorized = False
    device.classification_status = "normal"
    device.status = "online"
    device.first_seen = datetime.now()
    device.last_seen = datetime.now()

    db = MagicMock()
    db.get.return_value = device

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db

    try:
        client = TestClient(app)
        res_50 = client.patch("/devices/1/vlan", json={"vlan_id": 50})
        assert res_50.status_code == 200
        assert device.vlan_id == 50

        res_60 = client.patch("/devices/1/vlan", json={"vlan_id": 60})
        assert res_60.status_code == 200
        assert device.vlan_id == 60
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_set_device_type_to_server_and_access_point():
    from fastapi.testclient import TestClient
    from backend.app.database import get_db
    from backend.app.main import app

    device = make_device("02:AA:BB:CC:DD:66")
    device.device_type = "unknown"
    device.vlan_id = 90
    device.approval_status = "pending"
    device.enforcement_status = "quarantined"
    device.internet_access_authorized = False
    device.classification_status = "normal"
    device.status = "online"
    device.first_seen = datetime.now()
    device.last_seen = datetime.now()

    db = MagicMock()
    db.get.return_value = device

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db

    try:
        client = TestClient(app)
        res_server = client.patch("/devices/1/type", json={"device_type": "server"})
        assert res_server.status_code == 200
        assert device.device_type == "server"
        assert device.vlan_id == 50

        res_ap = client.patch("/devices/1/type", json={"device_type": "access_point"})
        assert res_ap.status_code == 200
        assert device.device_type == "access_point"
        assert device.vlan_id == 60
    finally:
        app.dependency_overrides.pop(get_db, None)


