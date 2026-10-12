from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from backend.app.api import simulation


def make_db():
    db = MagicMock()
    db.scalar.return_value = None

    added_devices = []

    def add_device(device):
        device.id = len(added_devices) + 1
        added_devices.append(device)

    db.add.side_effect = add_device
    return db, added_devices


def test_seed_creates_four_quarantined_simulation_devices(monkeypatch):
    db, added_devices = make_db()
    event_mock = MagicMock()
    monkeypatch.setattr(simulation, "create_event", event_mock)

    result = simulation.seed_simulation_devices(db)

    assert result["mode"] == "simulation"
    assert result["hardware_accessed"] is False
    assert result["created_count"] == 4
    assert result["already_present_count"] == 0
    assert len(added_devices) == 4

    expected = {
        "SIM-PC-01": ("computer", 20),
        "SIM-CCTV-01": ("cctv", 30),
        "SIM-PRINTER-01": ("printer", 40),
        "SIM-UNKNOWN-01": ("unknown", 90),
    }

    for device in added_devices:
        expected_type, expected_vlan = expected[device.hostname]

        assert (device.device_type or "unknown") == expected_type
        assert device.vlan_id == expected_vlan
        assert device.approval_status == "pending"
        assert device.enforcement_status == "quarantined"
        assert device.internet_access_authorized is False
        assert "NETOPS SIMULATION:" in device.notes

    assert event_mock.call_count == 4
    db.commit.assert_called_once()


def test_seed_is_idempotent_for_existing_simulation_devices(monkeypatch):
    db = MagicMock()
    event_mock = MagicMock()
    monkeypatch.setattr(simulation, "create_event", event_mock)

    existing_devices = [
        SimpleNamespace(
            mac_address=sample["mac_address"],
            notes=simulation.SIMULATION_NOTE,
        )
        for sample in simulation.SAMPLE_DEVICES
    ]
    db.scalar.side_effect = existing_devices

    result = simulation.seed_simulation_devices(db)

    assert result["created_count"] == 0
    assert result["already_present_count"] == 4
    assert len(result["already_present"]) == 4
    db.add.assert_not_called()
    db.commit.assert_called_once()
    event_mock.assert_not_called()


def test_seed_refuses_to_reuse_a_real_device_mac():
    db = MagicMock()
    db.scalar.return_value = SimpleNamespace(
        mac_address=simulation.SAMPLE_DEVICES[0]["mac_address"],
        notes="Real device record",
    )

    with pytest.raises(HTTPException) as exc_info:
        simulation.seed_simulation_devices(db)

    assert exc_info.value.status_code == 409
    db.add.assert_not_called()
    db.commit.assert_not_called()
