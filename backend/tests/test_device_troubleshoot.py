"""
Tests for Device Troubleshooting & Diagnostics API.
"""

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models.device import Device
from backend.app.models.event import Event


TEST_DB_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_troubleshoot_device_not_found(client):
    res = client.post("/devices/9999/troubleshoot")
    assert res.status_code == 404
    assert res.json()["detail"] == "Device not found"


def test_troubleshoot_device_ip_drift_detected(client, db_session):
    dev = Device(
        hostname="Test-Mikrotik",
        ip_address="192.168.0.11",
        mac_address="2C:C8:1B:EA:E5:E2",
        device_type="computer",
        status="offline",
        approval_status="approved",
        vlan_id=20,
        enforcement_status="allowed",
        internet_access_authorized=True,
    )
    db_session.add(dev)
    db_session.commit()
    db_session.refresh(dev)

    # Mock mac scan finding the MAC at 192.168.0.15
    with patch(
        "backend.app.services.device_troubleshooter._scan_lan_mac_addresses",
        return_value={
            "2CC81BEAE5E2": {
                "ip_address": "192.168.0.15",
                "mac_address": "2C:C8:1B:EA:E5:E2",
                "vendor": "Routerboard.com",
                "interface": "eth0",
            }
        },
    ), patch(
        "backend.app.services.device_troubleshooter._check_arp_on_interface",
        return_value=(False, "Timeout"),
    ), patch(
        "backend.app.services.device_troubleshooter._check_ping_on_interface",
        return_value=(False, "100% loss"),
    ):
        res = client.post(f"/devices/{dev.id}/troubleshoot")
        assert res.status_code == 200
        data = res.json()

        assert data["diagnosed_status"] == "ip_mismatch"
        assert data["detected_ip"] == "192.168.0.15"
        assert data["can_auto_fix"] is True
        assert len(data["probable_causes"]) > 0
        assert "DHCP IP Reassignment" in data["probable_causes"][0]
        assert len(data["recommendations"]) > 0


def test_troubleshoot_device_firewall_icmp_blocked(client, db_session):
    dev = Device(
        hostname="Windows-Workstation",
        ip_address="192.168.0.12",
        mac_address="F0:1F:AF:4C:6A:E9",
        device_type="computer",
        status="offline",
        approval_status="approved",
        vlan_id=20,
        enforcement_status="allowed",
        internet_access_authorized=True,
    )
    db_session.add(dev)
    db_session.commit()
    db_session.refresh(dev)

    # ARP succeeds on eth0, but ping and tcp fail
    def mock_arp(ip, iface, timeout=2):
        return (True, "ARP reply") if iface == "eth0" else (False, "Timeout")

    with patch(
        "backend.app.services.device_troubleshooter._check_arp_on_interface",
        side_effect=mock_arp,
    ), patch(
        "backend.app.services.device_troubleshooter._check_ping_on_interface",
        return_value=(False, "100% loss"),
    ), patch(
        "backend.app.services.device_troubleshooter._probe_tcp_port",
        return_value=False,
    ), patch(
        "backend.app.services.device_troubleshooter._scan_lan_mac_addresses",
        return_value={
            "F01FAF4C6AE9": {
                "ip_address": "192.168.0.12",
                "mac_address": "F0:1F:AF:4C:6A:E9",
                "vendor": "Dell Inc.",
                "interface": "eth0",
            }
        },
    ):
        res = client.post(f"/devices/{dev.id}/troubleshoot")
        assert res.status_code == 200
        data = res.json()

        assert data["diagnosed_status"] == "firewall_icmp_blocked"
        assert "Firewall is Dropping Ping" in data["verdict"]
        assert data["can_auto_fix"] is True
        # Device was synced to online in DB
        db_session.refresh(dev)
        assert dev.status == "online"


def test_troubleshoot_device_offline_unreachable(client, db_session):
    dev = Device(
        hostname="Powered-Off-Printer",
        ip_address="192.168.0.40",
        mac_address="AA:BB:CC:DD:EE:FF",
        device_type="printer",
        status="offline",
        approval_status="approved",
        vlan_id=40,
        enforcement_status="allowed",
    )
    db_session.add(dev)
    db_session.commit()
    db_session.refresh(dev)

    with patch(
        "backend.app.services.device_troubleshooter._check_arp_on_interface",
        return_value=(False, "Timeout"),
    ), patch(
        "backend.app.services.device_troubleshooter._check_ping_on_interface",
        return_value=(False, "Timeout"),
    ), patch(
        "backend.app.services.device_troubleshooter._probe_tcp_port",
        return_value=False,
    ), patch(
        "backend.app.services.device_troubleshooter._scan_lan_mac_addresses",
        return_value={},
    ):
        res = client.post(f"/devices/{dev.id}/troubleshoot")
        assert res.status_code == 200
        data = res.json()

        assert data["diagnosed_status"] == "offline_unreachable"
        assert "Disconnected or Powered Off" in data["verdict"]
        assert len(data["probable_causes"]) > 0
        assert len(data["recommendations"]) > 0


def test_apply_troubleshoot_fix_update_ip(client, db_session):
    dev = Device(
        hostname="DHCP-Client",
        ip_address="192.168.0.50",
        mac_address="11:22:33:44:55:66",
        device_type="computer",
        status="offline",
        approval_status="approved",
        vlan_id=20,
        enforcement_status="allowed",
        internet_access_authorized=True,
    )
    db_session.add(dev)
    db_session.commit()
    db_session.refresh(dev)

    res = client.post(
        f"/devices/{dev.id}/troubleshoot/apply-fix",
        json={"action": "update_ip", "new_ip": "192.168.0.55"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["ip_address"] == "192.168.0.55"
    assert data["status"] == "online"

    db_session.refresh(dev)
    assert dev.ip_address == "192.168.0.55"
    assert dev.status == "online"
