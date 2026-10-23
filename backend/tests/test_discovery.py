from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.database import Base
from backend.app.services.discovery import discover_devices

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



@pytest.mark.parametrize(
    "network",
    [
        "not-a-network",
        "192.168.1.5",
        "192.168.1.0/33",
        "",
    ],
)
def test_discovery_rejects_invalid_network_without_scanning(network):
    with patch(
        "backend.app.services.discovery.subprocess.run"
    ) as mock_run:
        with pytest.raises(ValueError):
            discover_devices(network)

    mock_run.assert_not_called()

def test_discovery_rejects_empty_network_without_scanning():
    from unittest.mock import patch

    with patch(
        "backend.app.services.discovery.subprocess.run"
    ) as mock_run:
        with pytest.raises(ValueError):
            discover_devices("")

    mock_run.assert_not_called()

def test_discovery_nmap_timeout():
    from unittest.mock import patch
    import subprocess

    with (
        patch(
            "backend.app.services.discovery.get_local_ip",
            return_value="192.168.1.10",
        ),
        patch(
            "backend.app.services.discovery.get_local_mac",
            return_value="AA:BB:CC:DD:EE:FF",
        ),
        patch(
            "backend.app.services.discovery.subprocess.run",
            side_effect=subprocess.TimeoutExpired(
                cmd="nmap",
                timeout=60,
            ),
        ) as mock_run,
    ):
        with pytest.raises(subprocess.TimeoutExpired):
            discover_devices("192.168.1.0/24")

    mock_run.assert_called_once()


def test_save_discovered_devices_ip_migration(db_session):
    from backend.app.models.device import Device
    from backend.app.models.event import Event
    from backend.app.services.discovery import save_discovered_devices

    # Device already exists with old IP
    existing = Device(
        mac_address="F0:1F:AF:4C:6A:E9",
        ip_address="192.168.0.11",
        hostname="DELL-PC",
        vendor="Dell",
        device_type="computer",
        approval_status="approved",
        status="online",
        internet_access_authorized=True,
    )
    db_session.add(existing)

    # Another stale device with 192.168.0.12
    stale = Device(
        mac_address="AA:BB:CC:11:22:33",
        ip_address="192.168.0.12",
        hostname="OLD-DEVICE",
        status="offline",
    )
    db_session.add(stale)
    db_session.commit()

    discovered = [
        {
            "mac_address": "F0:1F:AF:4C:6A:E9",
            "ip_address": "192.168.0.12",
            "hostname": "DELL-PC",
            "vendor": "Dell",
            "device_type": "computer",
        }
    ]

    with (
        patch("backend.app.services.discovery.is_sophos_configured", return_value=True),
        patch("backend.app.services.discovery.sophos_allow_device") as mock_sophos_allow,
        patch("backend.app.services.discovery.enforce_device_access") as mock_enforce,
    ):
        saved = save_discovered_devices(discovered, db_session)

        # Existing device IP should be updated to 192.168.0.12
        assert len(saved) == 1
        assert saved[0].ip_address == "192.168.0.12"
        assert saved[0].id == existing.id

        # Stale device's conflicting IP should be cleared
        db_session.refresh(stale)
        assert stale.ip_address is None

        # Old IP 192.168.0.11 should be unblocked on Sophos
        mock_sophos_allow.assert_called_once_with("192.168.0.11")

        # enforce_device_access should be called with force=True
        mock_enforce.assert_called_once_with(existing, db_session, force=True)

        # ip_address_changed and new_device events should be logged
        evt = db_session.query(Event).filter(
            Event.device_id == existing.id,
            Event.event_type == "ip_address_changed",
        ).first()
        assert evt is not None
        assert "192.168.0.11 to 192.168.0.12" in evt.message

        # Device is DHCP by default, so it is treated as a new machine (quarantined, pending approval)
        assert saved[0].approval_status == "pending"
        assert saved[0].internet_access_authorized is False
        assert saved[0].vlan_id == 90
        assert saved[0].enforcement_status == "quarantined"

        new_dev_evt = db_session.query(Event).filter(
            Event.device_id == existing.id,
            Event.event_type == "new_device",
        ).first()
        assert new_dev_evt is not None
        assert "Treated as new machine" in new_dev_evt.message


def test_save_discovered_devices_static_ip_mismatch_creates_conflict_event(db_session):
    from backend.app.models.device import Device
    from backend.app.models.event import Event
    from backend.app.services.discovery import save_discovered_devices

    # Device configured with a static IP
    static_dev = Device(
        mac_address="F0:1F:AF:4C:6A:E9",
        ip_address="192.168.0.11",
        hostname="STATIC-SERVER",
        vendor="Dell",
        device_type="computer",
        approval_status="approved",
        status="online",
        ip_assignment="static",
        internet_access_authorized=True,
    )
    db_session.add(static_dev)
    db_session.commit()

    discovered = [
        {
            "mac_address": "F0:1F:AF:4C:6A:E9",
            "ip_address": "192.168.0.12",
            "hostname": "STATIC-SERVER",
            "vendor": "Dell",
            "device_type": "computer",
        }
    ]

    with (
        patch("backend.app.services.discovery.is_sophos_configured", return_value=False),
        patch("backend.app.services.discovery.enforce_device_access"),
    ):
        saved = save_discovered_devices(discovered, db_session)

        assert len(saved) == 1
        assert saved[0].ip_address == "192.168.0.12"

        # Static device should NOT be reset to pending approval, but emit ip_address_conflict
        conflict_evt = db_session.query(Event).filter(
            Event.device_id == static_dev.id,
            Event.event_type == "ip_address_conflict",
        ).first()
        assert conflict_evt is not None
        assert "Static IP mismatch" in conflict_evt.message


def test_save_discovered_devices_marks_disconnected_device_offline(db_session):
    from backend.app.models.device import Device
    from backend.app.models.event import Event
    from backend.app.services.discovery import save_discovered_devices

    # Device exists and is currently marked online
    device_online = Device(
        mac_address="7C:5A:1C:A4:0B:10",
        ip_address="192.168.0.50",
        hostname="WORKSTATION-DISCONNECTED",
        vendor="Intel",
        device_type="computer",
        approval_status="approved",
        status="online",
    )
    db_session.add(device_online)
    db_session.commit()

    # Scan discovers NOTHING (e.g. workstation unplugged)
    saved = save_discovered_devices([], db_session)

    db_session.refresh(device_online)
    assert device_online.status == "offline"

    evt = db_session.query(Event).filter(
        Event.device_id == device_online.id,
        Event.event_type == "device_offline",
    ).first()
    assert evt is not None
    assert "went offline / disconnected from the LAN" in evt.message

