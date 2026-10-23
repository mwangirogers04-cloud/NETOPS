from datetime import datetime, time
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.database import Base
from backend.app.models.device import Device
from backend.app.models.event import Event
from backend.app.models.access_schedule import AccessSchedule
from backend.app.services.network_enforcement import enforce_device_access
from backend.app.services.combined_access import get_combined_access_decision


TEST_DB_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


def test_recognized_quarantined_device_auto_approves_and_returns_online_on_schedule(db_session):
    """
    If a machine is scheduled for internet access and is recognized, when the scheduled
    time comes, it should automatically return online from quarantine on its operational
    VLAN without requiring manual administrator approval again.
    """
    dev = Device(
        mac_address="AA:BB:CC:DD:EE:01",
        ip_address="192.168.0.101",
        hostname="WORKSTATION-01",
        vendor="Dell Inc.",
        device_type="computer",
        approval_status="pending",
        enforcement_status="quarantined",
        internet_access_authorized=False,
        vlan_id=90,
        status="offline",
    )
    db_session.add(dev)
    db_session.commit()
    db_session.refresh(dev)

    schedule = AccessSchedule(
        device_id=dev.id,
        enabled=True,
        days="daily",
        start_time=time(8, 0, 0),
        end_time=time(18, 0, 0),
    )
    db_session.add(schedule)
    db_session.commit()

    with (
        patch("backend.app.services.network_enforcement.is_access_allowed", return_value=True),
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.restore_device_l2") as mock_restore_l2,
    ):
        res = enforce_device_access(dev, db_session, force=True)

        assert res["decision"] == "allowed"
        assert res["enforcement_status"] == "allowed"
        assert dev.approval_status == "approved"
        assert dev.internet_access_authorized is True
        assert dev.vlan_id == 20  # Operational VLAN for computer
        assert dev.status == "online"
        mock_restore_l2.assert_called_once()

        db_session.commit()

        # Audit event for auto-restoration
        events = db_session.query(Event).filter(
            Event.device_id == dev.id,
            Event.event_type == "scheduled_access_allowed",
        ).all()
        assert len(events) == 1
        assert "automatically returned online from quarantine on VLAN 20" in events[0].message
        assert "without requiring administrator approval" in events[0].message


def test_device_outside_schedule_window_remains_quarantined(db_session):
    """
    Outside scheduled hours, device remains quarantined with access disabled,
    but retains its recognized/approved state.
    """
    dev = Device(
        mac_address="AA:BB:CC:DD:EE:02",
        ip_address="192.168.0.102",
        hostname="WORKSTATION-02",
        vendor="Dell Inc.",
        device_type="computer",
        approval_status="approved",
        enforcement_status="allowed",
        internet_access_authorized=True,
        vlan_id=20,
        status="online",
    )
    db_session.add(dev)
    db_session.commit()
    db_session.refresh(dev)

    schedule = AccessSchedule(
        device_id=dev.id,
        enabled=True,
        days="daily",
        start_time=time(8, 0, 0),
        end_time=time(17, 0, 0),
    )
    db_session.add(schedule)
    db_session.commit()

    with (
        patch("backend.app.services.network_enforcement.is_access_allowed", return_value=False),
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.quarantine_device_l2") as mock_quarantine_l2,
    ):
        res = enforce_device_access(dev, db_session, force=True)

        assert res["decision"] == "quarantine"
        assert res["enforcement_status"] == "quarantined"
        assert dev.internet_access_authorized is False
        assert dev.vlan_id == 90
        # Retains approval status so next window opens seamlessly
        assert dev.approval_status == "approved"

        db_session.commit()
        quar_evts = db_session.query(Event).filter(
            Event.device_id == dev.id,
            Event.event_type == "scheduled_access_quarantined",
        ).all()
        assert len(quar_evts) == 1
        assert "automatically moved to quarantine on VLAN 90" in quar_evts[0].message


def test_quarantined_device_auto_returns_online_when_schedule_window_opens(db_session):
    """
    Full cycle: device was quarantined outside hours; when scheduled time comes,
    it automatically returns online without administrator intervention.
    """
    dev = Device(
        mac_address="AA:BB:CC:DD:EE:03",
        ip_address="192.168.0.103",
        hostname="PRINTER-01",
        vendor="HP",
        device_type="printer",
        approval_status="approved",
        enforcement_status="quarantined",
        internet_access_authorized=False,
        vlan_id=90,
        status="online",
    )
    db_session.add(dev)
    db_session.commit()
    db_session.refresh(dev)

    schedule = AccessSchedule(
        device_id=dev.id,
        enabled=True,
        days="daily",
        start_time=time(9, 0, 0),
        end_time=time(17, 0, 0),
    )
    db_session.add(schedule)
    db_session.commit()

    with (
        patch("backend.app.services.network_enforcement.is_access_allowed", return_value=True),
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.restore_device_l2") as mock_restore,
    ):
        res = enforce_device_access(dev, db_session, force=True)

        assert res["decision"] == "allowed"
        assert dev.enforcement_status == "allowed"
        assert dev.internet_access_authorized is True
        assert dev.vlan_id == 40  # Operational VLAN for printer
        mock_restore.assert_called_once()


def test_isolated_device_is_never_auto_restored_by_schedule(db_session):
    """
    An explicitly isolated device must strictly stay isolated in VLAN 90
    even if an active schedule matches.
    """
    dev = Device(
        mac_address="AA:BB:CC:DD:EE:04",
        ip_address="192.168.0.104",
        hostname="INFECTED-PC",
        device_type="computer",
        approval_status="approved",
        enforcement_status="isolated",
        internet_access_authorized=False,
        vlan_id=90,
        status="online",
    )
    db_session.add(dev)
    db_session.commit()
    db_session.refresh(dev)

    schedule = AccessSchedule(
        device_id=dev.id,
        enabled=True,
        days="daily",
        start_time=time(8, 0, 0),
        end_time=time(18, 0, 0),
    )
    db_session.add(schedule)
    db_session.commit()

    with (
        patch("backend.app.services.network_enforcement.is_access_allowed", return_value=True),
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
    ):
        res = enforce_device_access(dev, db_session, force=True)

        assert res["decision"] == "isolated"
        assert res["enforcement_status"] == "isolated"
        assert dev.internet_access_authorized is False
        assert dev.vlan_id == 90


def test_unrecognized_device_is_not_auto_approved_by_schedule(db_session):
    """
    An unrecognized / unclassified device must not be auto-approved into
    an operational VLAN; it must remain quarantined.
    """
    dev = Device(
        mac_address="00:00:00:00:00:99",
        ip_address="192.168.0.199",
        hostname="UNKNOWN-ROGUE",
        device_type=None,
        approval_status="pending",
        enforcement_status="quarantined",
        internet_access_authorized=False,
        vlan_id=90,
        status="online",
    )
    db_session.add(dev)
    db_session.commit()
    db_session.refresh(dev)

    schedule = AccessSchedule(
        device_id=dev.id,
        enabled=True,
        days="daily",
        start_time=time(8, 0, 0),
        end_time=time(18, 0, 0),
    )
    db_session.add(schedule)
    db_session.commit()

    with (
        patch("backend.app.services.network_enforcement.is_access_allowed", return_value=True),
        patch("backend.app.services.network_enforcement.classify_device", return_value="unknown"),
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
    ):
        res = enforce_device_access(dev, db_session, force=True)

        assert res["decision"] == "quarantine"
        assert res["enforcement_status"] == "quarantined"
        assert dev.approval_status == "pending"
        assert dev.internet_access_authorized is False
        assert dev.vlan_id == 90


def test_combined_access_decision_scheduled_recognized_device(db_session):
    """
    Test get_combined_access_decision handles recognized scheduled devices
    seamlessly without requiring pre-approval.
    """
    dev = Device(
        mac_address="AA:BB:CC:DD:EE:05",
        ip_address="192.168.0.105",
        hostname="CAMERA-01",
        device_type="cctv",
        approval_status="pending",
        enforcement_status="quarantined",
        internet_access_authorized=False,
        vlan_id=90,
        status="online",
    )
    db_session.add(dev)
    db_session.commit()
    db_session.refresh(dev)

    schedule = AccessSchedule(
        device_id=dev.id,
        enabled=True,
        days="daily",
        start_time=time(0, 0, 0),
        end_time=time(23, 59, 59),
    )
    db_session.add(schedule)
    db_session.commit()

    with patch("backend.app.services.combined_access.is_access_allowed", return_value=True):
        decision = get_combined_access_decision(dev, db_session)

        assert decision["decision"] == "allowed"
        assert decision["action"] == "allow"
        assert decision["schedule_allows_access"] is True
