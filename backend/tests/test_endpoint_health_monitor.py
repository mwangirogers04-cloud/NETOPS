import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from backend.app.models.endpoint_update import EndpointUpdate
from backend.app.services import endpoint_health_monitor as monitor


def test_stale_endpoint_creates_stale_event(monkeypatch):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    report = MagicMock(spec=EndpointUpdate)
    report.hostname = "TEST-PC"
    report.machine_id = "test-machine-001"
    report.mac_address = "AA:BB:CC:DD:EE:11"
    report.last_checked = now - timedelta(minutes=20)

    db = MagicMock()
    db.scalars.return_value.all.return_value = [report]
    db.scalars.return_value.first.return_value = None

    monkeypatch.setattr(
        monitor, "SessionLocal", MagicMock(return_value=db)
    )

    event_mock = MagicMock()
    monkeypatch.setattr(monitor, "create_event", event_mock)

    async def stop_after_one_cycle(_seconds):
        raise RuntimeError("stop test loop")

    monkeypatch.setattr(
        monitor.asyncio, "sleep", stop_after_one_cycle
    )

    try:
        asyncio.run(monitor.endpoint_health_monitor_loop())
    except RuntimeError as error:
        assert str(error) == "stop test loop"
    else:
        raise AssertionError("Monitor did not stop as expected")

    stale_calls = [
        call
        for call in event_mock.call_args_list
        if call.kwargs.get("event_type") == "endpoint_stale"
    ]

    assert len(stale_calls) == 1
    assert "TEST-PC" in stale_calls[0].kwargs["message"]
    assert "Endpoint key: machine:test-machine-001" in (
        stale_calls[0].kwargs["message"]
    )

    db.commit.assert_called_once()
    db.close.assert_called_once()

def test_recovered_endpoint_creates_recovery_event(monkeypatch):
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    report = MagicMock(spec=EndpointUpdate)
    report.hostname = "TEST-PC"
    report.machine_id = "test-machine-001"
    report.mac_address = "AA:BB:CC:DD:EE:11"
    report.last_checked = now - timedelta(minutes=2)

    previous_event = MagicMock()
    previous_event.event_type = "endpoint_stale"

    db = MagicMock()
    db.scalars.return_value.all.return_value = [report]
    db.scalars.return_value.first.return_value = previous_event

    monkeypatch.setattr(
        monitor, "SessionLocal", MagicMock(return_value=db)
    )

    event_mock = MagicMock()
    monkeypatch.setattr(monitor, "create_event", event_mock)

    async def stop_after_one_cycle(_seconds):
        raise RuntimeError("stop test loop")

    monkeypatch.setattr(
        monitor.asyncio, "sleep", stop_after_one_cycle
    )

    try:
        asyncio.run(monitor.endpoint_health_monitor_loop())
    except RuntimeError as error:
        assert str(error) == "stop test loop"
    else:
        raise AssertionError("Monitor did not stop as expected")

    recovery_calls = [
        call
        for call in event_mock.call_args_list
        if call.kwargs.get("event_type") == "endpoint_recovered"
    ]

    assert len(recovery_calls) == 1
    assert "TEST-PC" in recovery_calls[0].kwargs["message"]
    assert "Endpoint key: machine:test-machine-001" in (
        recovery_calls[0].kwargs["message"]
    )

    db.commit.assert_called_once()
    db.close.assert_called_once()
def test_already_stale_endpoint_does_not_create_duplicate_event(monkeypatch):
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    report = MagicMock(spec=EndpointUpdate)
    report.hostname = "TEST-PC"
    report.machine_id = "test-machine-001"
    report.mac_address = "AA:BB:CC:DD:EE:11"
    report.last_checked = now - timedelta(minutes=20)

    previous_event = MagicMock()
    previous_event.event_type = "endpoint_stale"

    db = MagicMock()
    db.scalars.return_value.all.return_value = [report]
    db.scalars.return_value.first.return_value = previous_event

    monkeypatch.setattr(
        monitor, "SessionLocal", MagicMock(return_value=db)
    )

    event_mock = MagicMock()
    monkeypatch.setattr(monitor, "create_event", event_mock)

    async def stop_after_one_cycle(_seconds):
        raise RuntimeError("stop test loop")

    monkeypatch.setattr(
        monitor.asyncio, "sleep", stop_after_one_cycle
    )

    try:
        asyncio.run(monitor.endpoint_health_monitor_loop())
    except RuntimeError as error:
        assert str(error) == "stop test loop"
    else:
        raise AssertionError("Monitor did not stop as expected")

    stale_calls = [
        call
        for call in event_mock.call_args_list
        if call.kwargs.get("event_type") == "endpoint_stale"
    ]

    assert len(stale_calls) == 0
    db.commit.assert_called_once()
    db.close.assert_called_once()
