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


def test_scheduled_device_remains_quarantined_until_start_time_then_accesses_and_quarantines(db_session):
    """
    User scenario:
    If a device is quarantined / disconnected, once it's scheduled (e.g. 18:10 to 18:30, at 18:05):
    1. At 18:05 (before window): remains quarantined in VLAN 90 with no internet access.
    2. At 18:10 (window opens): gets out of quarantine to VLAN 20 and accesses internet.
    3. At 18:30 (window closes): automatically quarantines itself back to VLAN 90 until next cycle.
    """
    from backend.app.services.access_schedule import is_access_allowed

    dev = Device(
        mac_address="AA:BB:CC:DD:EE:77",
        ip_address="192.168.0.77",
        hostname="PC-SCHEDULE-TEST",
        vendor="Dell",
        device_type="computer",
        approval_status="approved",
        enforcement_status="quarantined",
        internet_access_authorized=False,
        vlan_id=90,
        status="online",
    )
    db_session.add(dev)
    db_session.commit()
    db_session.refresh(dev)

    # Schedule created today at 18:05 for window 18:10:00 - 18:30:00
    today = datetime(2026, 10, 24, 18, 5, 0)
    schedule = AccessSchedule(
        device_id=dev.id,
        enabled=True,
        days="daily",
        start_time=time(18, 10, 0),
        end_time=time(18, 30, 0),
        created_at=today,
        updated_at=today,
    )
    db_session.add(schedule)
    db_session.commit()

    # Step 1: At 18:05 (when scheduled):
    # Should NOT come out of quarantine; must remain quarantined!
    allowed_at_1805 = is_access_allowed(
        db_session,
        dev.id,
        current_time=time(18, 5, 0),
        current_datetime=datetime(2026, 10, 24, 18, 5, 0),
    )
    assert allowed_at_1805 is False

    with (
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.quarantine_device_l2"),
    ):
        res = enforce_device_access(
            dev,
            db_session,
            current_datetime=datetime(2026, 10, 24, 18, 5, 0),
            force=True,
        )
        assert res["decision"] == "quarantine"
        assert res["enforcement_status"] == "quarantined"
        assert dev.vlan_id == 90
        assert dev.internet_access_authorized is False

    # Step 2: At 18:10 (window opens):
    # Comes out of quarantine to VLAN 20 and accesses internet!
    allowed_at_1810 = is_access_allowed(
        db_session,
        dev.id,
        current_time=time(18, 10, 0),
        current_datetime=datetime(2026, 10, 24, 18, 10, 0),
    )
    assert allowed_at_1810 is True

    with (
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.restore_device_l2"),
    ):
        res_allowed = enforce_device_access(
            dev,
            db_session,
            current_datetime=datetime(2026, 10, 24, 18, 10, 0),
            force=True,
        )
        assert res_allowed["decision"] == "allowed"
        assert res_allowed["enforcement_status"] == "allowed"
        assert dev.vlan_id == 20
        assert dev.internet_access_authorized is True

    # Step 3: At 18:31 (window ends):
    # Quarantines itself back to VLAN 90 until next cycle!
    allowed_at_1831 = is_access_allowed(
        db_session,
        dev.id,
        current_time=time(18, 31, 0),
        current_datetime=datetime(2026, 10, 24, 18, 31, 0),
    )
    assert allowed_at_1831 is False

    with (
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.quarantine_device_l2"),
    ):
        res_quar = enforce_device_access(
            dev,
            db_session,
            current_datetime=datetime(2026, 10, 24, 18, 31, 0),
            force=True,
        )
        assert res_quar["decision"] == "quarantine"
        assert res_quar["enforcement_status"] == "quarantined"
        assert dev.vlan_id == 90
        assert dev.internet_access_authorized is False


def test_reset_device_schedules_removes_device_from_quarantine_and_awaits_next_schedule(db_session):
    """
    Resetting all schedules for a device removes it from quarantine (restoring operational VLAN),
    marks it approved, restores internet access authorization, and sets enforcement to allowed
    awaiting any future schedule.
    """
    from backend.app.api.access_schedules import reset_device_schedules

    dev = Device(
        mac_address="AA:BB:CC:DD:EE:77",
        ip_address="192.168.0.77",
        hostname="ACCOUNTING-PC",
        vendor="Dell Inc.",
        device_type="computer",
        approval_status="approved",
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
        start_time=time(20, 55, 0),
        end_time=time(21, 0, 0),
    )
    db_session.add(schedule)
    db_session.commit()

    with (
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.restore_device_l2") as mock_restore_l2,
    ):
        result = reset_device_schedules(dev.id, db=db_session)

        assert result["message"] == "Access schedule reset successfully"
        assert result["device_id"] == dev.id
        assert result["deleted_count"] == 1
        assert result["vlan_id"] == 20
        assert result["enforcement_status"] == "allowed"
        assert result["approval_status"] == "approved"

        # Check device state in DB
        db_session.refresh(dev)
        assert dev.vlan_id == 20
        assert dev.internet_access_authorized is True
        assert dev.approval_status == "approved"
        assert dev.status == "online"
        assert dev.enforcement_status == "allowed"

        # Check schedule was deleted
        remaining_schedules = db_session.query(AccessSchedule).filter(AccessSchedule.device_id == dev.id).all()
        assert len(remaining_schedules) == 0

        # Check audit event was created
        events = db_session.query(Event).filter(
            Event.device_id == dev.id,
            Event.event_type == "schedule_reset",
        ).all()
        assert len(events) == 1
        assert "Removed from quarantine, restored to VLAN 20" in events[0].message
        mock_restore_l2.assert_called_once()


def test_delete_last_access_schedule_removes_device_from_quarantine(db_session):
    """
    Deleting the last schedule via delete_access_schedule endpoint removes the device from quarantine,
    restoring operational VLAN and online status.
    """
    from backend.app.api.access_schedules import delete_access_schedule

    dev = Device(
        mac_address="AA:BB:CC:DD:EE:88",
        ip_address="192.168.0.88",
        hostname="RESEARCH-LAPTOP",
        vendor="Lenovo",
        device_type="computer",
        approval_status="approved",
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
        start_time=time(14, 0, 0),
        end_time=time(16, 0, 0),
    )
    db_session.add(schedule)
    db_session.commit()
    db_session.refresh(schedule)

    with (
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.restore_device_l2") as mock_restore_l2,
    ):
        result = delete_access_schedule(schedule.id, db=db_session)
        assert result["message"] == "Access schedule deleted successfully"
        assert result["schedule_id"] == schedule.id

        db_session.refresh(dev)
        assert dev.vlan_id == 20
        assert dev.internet_access_authorized is True
        assert dev.approval_status == "approved"
        assert dev.status == "online"
        assert dev.enforcement_status == "allowed"

        events = db_session.query(Event).filter(
            Event.device_id == dev.id,
            Event.event_type == "schedule_reset",
        ).all()
        assert len(events) == 1
        assert "Removed from quarantine, restored to VLAN 20" in events[0].message
        mock_restore_l2.assert_called_once()


def test_rejected_device_scheduled_waits_for_admin_until_given_internet_access(db_session):
    """
    1. A new device is detected and rejected: denied internet and quarantined in VLAN 90.
    2. An access schedule is set for it.
    3. Outside scheduled time: no internet, quarantined.
    4. When scheduled time arrives: it does NOT get internet automatically; it MUST STILL WAIT
       for the admin or developer to give it internet access since it is a new/rejected device.
    5. Once the admin or developer approves/allows internet access:
       - During active schedule window: leaves quarantine and accesses internet on VLAN 20.
       - Outside schedule window: returns to quarantine.
    6. When schedule is reset: schedule is cleared without auto-approving if rejected.
    """
    from backend.app.api.devices import add_access_information, allow_device, approve_device
    from backend.app.api.access_schedules import reset_device_schedules

    dev = Device(
        mac_address="AA:BB:CC:DD:EE:77",
        ip_address="192.168.0.77",
        hostname="NEW-WORKSTATION-77",
        vendor="HP Inc.",
        device_type="computer",
        approval_status="rejected",
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
        end_time=time(17, 0, 0),
    )
    db_session.add(schedule)
    db_session.commit()
    db_session.refresh(schedule)

    # 1. Outside scheduled time: denied internet and quarantined in VLAN 90
    with (
        patch("backend.app.services.network_enforcement.is_access_allowed", return_value=False),
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.quarantine_device_l2") as mock_quar,
    ):
        res_outside = enforce_device_access(dev, db_session, force=True)
        assert res_outside["decision"] == "quarantine"
        assert dev.enforcement_status == "quarantined"
        assert dev.vlan_id == 90
        assert dev.internet_access_authorized is False

    # 2. When scheduled time reaches: STILL WAITS for admin/developer to give it internet access
    with (
        patch("backend.app.services.network_enforcement.is_access_allowed", return_value=True),
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.quarantine_device_l2"),
    ):
        res_sched = enforce_device_access(dev, db_session, force=True)
        # Even though schedule allows access, rejected device must wait for admin/dev
        assert res_sched["decision"] == "quarantine"
        assert dev.enforcement_status == "quarantined"
        assert dev.vlan_id == 90
        assert dev.internet_access_authorized is False
        assert dev.approval_status == "rejected"

        add_access_information(dev)
        assert dev.access_decision == "quarantine"
        assert dev.access_reason == "Rejected by administrator"

    # 3. Admin gives it internet access (approve and allow)
    dev.approval_status = "approved"
    dev.internet_access_authorized = True
    db_session.commit()

    # Now when scheduled time is reached, it leaves quarantine and accesses internet
    with (
        patch("backend.app.services.network_enforcement.is_access_allowed", return_value=True),
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.restore_device_l2") as mock_restore,
    ):
        res_allowed = enforce_device_access(dev, db_session, force=True)
        assert res_allowed["decision"] == "allowed"
        assert dev.enforcement_status == "allowed"
        assert dev.vlan_id == 20
        assert dev.internet_access_authorized is True
        mock_restore.assert_called_once()

    # Outside schedule window: returns to quarantine
    with (
        patch("backend.app.services.network_enforcement.is_access_allowed", return_value=False),
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.quarantine_device_l2"),
    ):
        res_back = enforce_device_access(dev, db_session, force=True)
        assert res_back["decision"] == "quarantine"
        assert dev.enforcement_status == "quarantined"
        assert dev.vlan_id == 90

    # 4. Resetting the schedule clears the schedule
    with (
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.restore_device_l2"),
    ):
        reset_res = reset_device_schedules(dev.id, db=db_session)
        assert "reset" in reset_res["message"].lower()

        remaining_scheds = db_session.query(AccessSchedule).filter(
            AccessSchedule.device_id == dev.id
        ).all()
        assert len(remaining_scheds) == 0


def test_deleted_device_denied_internet_access_and_quarantined_until_procedure(db_session):
    """
    If an existing device is deleted from the system:
    1. It is immediately denied internet access (firewall blocked and L2 quarantined).
    2. Its records are purged from the inventory.
    3. If it reconnects or is re-discovered, it is placed in Quarantine VLAN 90
       with pending approval and denied internet access until it goes through the procedure.
    """
    from backend.app.api.devices import delete_device_permanently
    from backend.app.services.discovery import save_discovered_devices

    dev = Device(
        mac_address="AA:BB:CC:DD:EE:99",
        ip_address="192.168.0.99",
        hostname="CORP-LAPTOP-99",
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

    dev_id = dev.id
    mac = dev.mac_address
    ip = dev.ip_address

    with (
        patch("backend.app.api.devices.quarantine_device_l2") as mock_l2_quar,
        patch("backend.app.api.devices.get_active_firewall_driver") as mock_fw_driver,
    ):
        mock_driver_instance = MagicMock()
        mock_fw_driver.return_value = mock_driver_instance
        mock_driver_instance.vendor = "simulation"
        mock_driver_instance.is_configured.return_value = True

        from backend.app.models.user import User
        super_user = User(username="developer", role="super_admin")
        res = delete_device_permanently(dev_id, db=db_session, current_user=super_user)
        assert res["status"] == "deleted"

        # 1. Device was immediately denied internet access via L2 quarantine & firewall
        mock_l2_quar.assert_called_once_with(ip, mac, burst=3, interface=None)
        mock_driver_instance.block_device.assert_called_once_with(ip, "CORP-LAPTOP-99", mac)

        # 2. Record purged from DB
        assert db_session.get(Device, dev_id) is None

    # 3. Deleted device reconnects and is detected by discovery
    discovered_packet = [
        {
            "ip_address": ip,
            "mac_address": mac,
            "hostname": "CORP-LAPTOP-99",
            "vendor": "Dell Inc.",
        }
    ]

    with (
        patch("backend.app.services.discovery.classify_device", return_value="computer"),
        patch("backend.app.services.discovery.enforce_device_access") as mock_enf,
    ):
        saved = save_discovered_devices(discovered_packet, db_session)
        assert len(saved) == 1
        reconnected_dev = saved[0]

        # Reconnecting device is treated as brand new: pending, quarantined in VLAN 90, no internet
        assert reconnected_dev.approval_status == "pending"
        assert reconnected_dev.enforcement_status == "quarantined"
        assert reconnected_dev.vlan_id == 90
        assert reconnected_dev.internet_access_authorized is False
        mock_enf.assert_called_once()


def test_disconnected_quarantined_device_scheduled_remains_quarantined_until_start_time(db_session):
    """
    Exact user scenario:
    1. A device is disconnected (disallowed): automatically goes to quarantine (VLAN 90).
    2. Then it is scheduled for internet access from 18:10 to 18:30 (current time 18:05).
    3. It MUST NOT come out of quarantine when scheduled! It must remain quarantined until 18:10.
    4. At 18:10: it leaves quarantine to VLAN 20 and accesses internet.
    5. At 18:30: it automatically quarantines itself back to VLAN 90 until next cycle.
    """
    from backend.app.api.devices import disallow_device
    from backend.app.api.access_schedules import create_access_schedule, AccessScheduleCreate
    from backend.app.services.access_schedule import is_access_allowed

    dev = Device(
        mac_address="AA:BB:CC:DD:EE:66",
        ip_address="192.168.0.66",
        hostname="SALES-LAPTOP-66",
        vendor="Lenovo",
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

    # 1. Admin disconnects device -> automatically goes to quarantine
    with (
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.quarantine_device_l2") as mock_quar,
    ):
        dis_res = disallow_device(dev.id, db=db_session)
        assert dis_res["enforcement_status"] == "quarantined"
        assert dev.enforcement_status == "quarantined"
        assert dev.vlan_id == 90
        assert dev.internet_access_authorized is False

    # 2. At 18:05, admin schedules it to get internet access from 18:10 to 18:30
    schedule_data = AccessScheduleCreate(
        device_id=dev.id,
        enabled=True,
        days="daily",
        start_time=time(18, 10, 0),
        end_time=time(18, 30, 0),
    )

    with (
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.quarantine_device_l2"),
        patch("backend.app.services.access_schedule.datetime") as mock_sched_dt,
        patch("backend.app.api.access_schedules.datetime") as mock_api_dt,
    ):
        mock_now = datetime(2026, 10, 24, 18, 5, 0)
        mock_sched_dt.now.return_value = mock_now
        mock_api_dt.now.return_value = mock_now

        # Schedule created at 18:05
        sch = create_access_schedule(schedule_data, db=db_session)
        assert sch.id is not None

        # Check: IT MUST NOT COME OUT OF QUARANTINE!
        db_session.refresh(dev)
        assert dev.enforcement_status == "quarantined"
        assert dev.vlan_id == 90
        assert dev.internet_access_authorized is False

    # 3. Time advances to 18:10 (window opens)
    # Now it gets out of quarantine and accesses internet
    with (
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.restore_device_l2") as mock_restore,
    ):
        res_open = enforce_device_access(
            dev,
            db_session,
            current_datetime=datetime(2026, 10, 24, 18, 10, 0),
            force=True,
        )
        assert res_open["decision"] == "allowed"
        assert dev.enforcement_status == "allowed"
        assert dev.vlan_id == 20
        assert dev.internet_access_authorized is True
        assert dev.status == "online"
        mock_restore.assert_called_once()

    # 4. Time reaches 18:30:01 (window closes)
    # It automatically quarantines itself back to VLAN 90 until next cycle and changes status to offline
    with (
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.quarantine_device_l2") as mock_quar2,
    ):
        res_close = enforce_device_access(
            dev,
            db_session,
            current_datetime=datetime(2026, 10, 24, 18, 30, 1),
            force=True,
        )
        assert res_close["decision"] == "quarantine"
        assert dev.enforcement_status == "quarantined"
        assert dev.vlan_id == 90
        assert dev.internet_access_authorized is False
        assert dev.status == "offline"
        mock_quar2.assert_called_once()


def test_device_isolation_and_quarantine_enforce_offline_until_allowed(db_session):
    """
    When a device is isolated or quarantined, its connection status must immediately
    change to offline until it is granted internet access (online).
    """
    dev = Device(
        mac_address="50:65:F3:11:22:33",
        ip_address="192.168.0.77",
        hostname="OFFICE-PC",
        vendor="Lenovo",
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

    # 1. Device is isolated -> immediately status becomes offline
    dev.enforcement_status = "isolated"
    dev.internet_access_authorized = False
    with (
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.quarantine_device_l2"),
    ):
        enforce_device_access(dev, db_session, force=True)
        assert dev.status == "offline"
        assert dev.enforcement_status == "isolated"

    # 2. Device unisolated to quarantined -> remains offline
    dev.enforcement_status = "quarantined"
    with (
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.quarantine_device_l2"),
    ):
        enforce_device_access(dev, db_session, force=True)
        assert dev.status == "offline"
        assert dev.enforcement_status == "quarantined"

    # 3. Device granted internet access (allowed) -> immediately status becomes online
    dev.internet_access_authorized = True
    dev.enforcement_status = "quarantined"
    dev.vlan_id = 20
    with (
        patch("backend.app.services.network_enforcement.is_sophos_configured", return_value=False),
        patch("backend.app.services.network_enforcement.restore_device_l2"),
    ):
        enforce_device_access(dev, db_session, force=True)
        assert dev.status == "online"
        assert dev.enforcement_status == "allowed"







