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


def test_online_endpoint_never_marked_stale(monkeypatch):
    from backend.app.models.device import Device
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    report = MagicMock(spec=EndpointUpdate)
    report.hostname = "ONLINE-PC"
    report.machine_id = "test-machine-002"
    report.mac_address = "AA:BB:CC:DD:EE:22"
    report.ip_address = "192.168.0.12"
    report.last_checked = now - timedelta(minutes=60)

    online_dev = Device(
        id=10,
        mac_address="AA:BB:CC:DD:EE:22",
        ip_address="192.168.0.12",
        hostname="ONLINE-PC",
        status="online",
    )

    db = MagicMock()
    def mock_scalars(query):
        mock_result = MagicMock()
        q_str = str(query).lower()
        if "device" in q_str:
            mock_result.all.return_value = [online_dev]
        else:
            mock_result.all.return_value = [report]
        mock_result.first.return_value = None
        return mock_result

    db.scalars.side_effect = mock_scalars

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

    stale_calls = [
        call
        for call in event_mock.call_args_list
        if call.kwargs.get("event_type") == "endpoint_stale"
    ]
    assert len(stale_calls) == 0
    db.commit.assert_called_once()
    db.close.assert_called_once()


def test_offline_device_reconnected_transitions_to_online(monkeypatch):
    from unittest.mock import patch
    from backend.app.models.device import Device
    dev = Device(
        id=46,
        mac_address="F0:1F:AF:4C:6A:E9",
        ip_address="192.168.0.12",
        hostname="HOST-192-168-0-12",
        status="offline",
    )
    # Use a dummy non-mock class for db so is_mock_env is False
    class RealDbSession:
        def __init__(self):
            self.committed = False
            self.closed = False
        def scalars(self, query):
            mock_res = MagicMock()
            q_str = str(query).lower()
            if "device" in q_str:
                mock_res.all.return_value = [dev]
            else:
                mock_res.all.return_value = []
            mock_res.first.return_value = None
            return mock_res
        def commit(self):
            self.committed = True
        def close(self):
            self.closed = True
        def rollback(self):
            pass

    db_instance = RealDbSession()
    monkeypatch.setattr(monitor, "SessionLocal", lambda: db_instance)
    event_mock = MagicMock()
    monkeypatch.setattr(monitor, "create_event", event_mock)

    async def stop_after_one_cycle(_seconds):
        raise RuntimeError("stop test loop")

    monkeypatch.setattr(monitor.asyncio, "sleep", stop_after_one_cycle)

    with patch("backend.app.services.endpoint_health_monitor.subprocess.run") as mock_subproc:
        fake_res = MagicMock()
        fake_res.stdout = "192.168.0.12\tF0:1F:AF:4C:6A:E9\tDell Inc."
        fake_res.returncode = 0
        mock_subproc.return_value = fake_res

        try:
            asyncio.run(monitor.endpoint_health_monitor_loop())
        except RuntimeError as err:
            assert str(err) == "stop test loop"

    assert dev.status == "online"
    online_calls = [
        c for c in event_mock.call_args_list if c.kwargs.get("event_type") == "device_online"
    ]
    assert online_calls[0].kwargs["device_id"] == dev.id
    assert db_instance.committed is True
    assert db_instance.closed is True


def test_endpoint_health_monitor_dhcp_ip_change_treated_as_new_machine(monkeypatch):
    from backend.app.models.device import Device
    from unittest.mock import patch

    dev = Device(
        id=42,
        mac_address="F0:1F:AF:4C:6A:E9",
        ip_address="192.168.0.10",
        hostname="HOST-192-168-0-10",
        vendor="Dell Inc.",
        status="online",
        approval_status="approved",
        ip_assignment="dhcp",
        vlan_id=20,
        enforcement_status="allowed",
        internet_access_authorized=True,
    )

    class RealDbSession:
        def __init__(self):
            self.committed = False
            self.closed = False
        def scalars(self, query):
            mock_res = MagicMock()
            q_str = str(query).lower()
            if "device" in q_str:
                mock_res.all.return_value = [dev]
            else:
                mock_res.all.return_value = []
            mock_res.first.return_value = None
            return mock_res
        def commit(self):
            self.committed = True
        def close(self):
            self.closed = True
        def rollback(self):
            pass

    db_instance = RealDbSession()
    monkeypatch.setattr(monitor, "SessionLocal", lambda: db_instance)
    event_mock = MagicMock()
    monkeypatch.setattr(monitor, "create_event", event_mock)

    async def stop_after_one_cycle(_seconds):
        raise RuntimeError("stop test loop")

    monkeypatch.setattr(monitor.asyncio, "sleep", stop_after_one_cycle)

    with (
        patch("backend.app.services.endpoint_health_monitor.subprocess.run") as mock_subproc,
        patch("backend.app.services.endpoint_health_monitor.enforce_device_access") as mock_enforce,
        patch("backend.app.services.endpoint_health_monitor.restore_device_l2"),
    ):
        fake_res = MagicMock()
        # live sweep finds device on a new DHCP IP (192.168.0.88)
        fake_res.stdout = "192.168.0.88\tF0:1F:AF:4C:6A:E9\tDell Inc."
        fake_res.returncode = 0
        mock_subproc.return_value = fake_res

        try:
            asyncio.run(monitor.endpoint_health_monitor_loop())
        except RuntimeError as err:
            assert str(err) == "stop test loop"

    # Device must be treated like a new machine
    assert dev.ip_address == "192.168.0.88"
    assert dev.approval_status == "pending"
    assert dev.vlan_id == 90
    assert dev.enforcement_status == "quarantined"
    assert dev.internet_access_authorized is False

    new_dev_calls = [
        c for c in event_mock.call_args_list if c.kwargs.get("event_type") == "new_device"
    ]
    assert len(new_dev_calls) == 1
    assert "Treated as new machine" in new_dev_calls[0].kwargs["message"]
    assert "192.168.0.10" in new_dev_calls[0].kwargs["message"]
    assert "192.168.0.88" in new_dev_calls[0].kwargs["message"]


