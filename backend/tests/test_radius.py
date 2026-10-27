"""
Unit and integration tests for 802.1X / FreeRADIUS Dynamic Port Assignment & MAB.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models.device import Device
from backend.app.models.switch_config import SwitchConfig
from backend.app.models.user import User
from backend.app.services.auth_service import hash_password, create_access_token
from backend.app.services.radius_service import (
    format_mac_for_radius,
    generate_freeradius_users_config,
    generate_freeradius_clients_config,
    simulate_radius_auth,
)

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def test_db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(test_db):
    app.dependency_overrides[get_db] = lambda: test_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def admin_headers(test_db):
    u = User(
        username="rad_admin",
        email="rad_admin@netops.local",
        hashed_password=hash_password("RadAdmin123!"),
        role="admin",
        is_active=True,
    )
    test_db.add(u)
    test_db.commit()
    token = create_access_token({"sub": "rad_admin", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


def test_format_mac_for_radius():
    """Verify MAC address formatting for various switch MAB conventions."""
    mac = "AA:BB:CC:DD:EE:FF"
    assert format_mac_for_radius(mac, "lowercase_nodelim") == "aabbccddeeff"
    assert format_mac_for_radius(mac, "colon") == "aa:bb:cc:dd:ee:ff"
    assert format_mac_for_radius(mac, "hyphen") == "aa-bb-cc-dd-ee-ff"
    assert format_mac_for_radius(mac, "cisco") == "aabb.ccdd.eeff"
    assert format_mac_for_radius(mac, "uppercase_nodelim") == "AABBCCDDEEFF"


def test_generate_freeradius_configs(test_db):
    """Verify generated FreeRADIUS users and clients.conf syntax."""
    dev1 = Device(
        mac_address="00:11:22:33:44:55",
        hostname="voip-phone-101",
        device_type="voip",
        approval_status="approved",
        enforcement_status="allowed",
        vlan_id=10,
    )
    dev2 = Device(
        mac_address="AA:BB:CC:DD:EE:FF",
        hostname="unapproved-laptop",
        device_type="computer",
        approval_status="pending",
        enforcement_status="quarantined",
        vlan_id=90,
    )
    sw = SwitchConfig(
        vendor="cisco_ios",
        name="Access Switch 1",
        management_ip="192.168.0.10",
        port=22,
        is_active=True,
    )
    test_db.add_all([dev1, dev2, sw])
    test_db.commit()

    users_text = generate_freeradius_users_config(test_db)
    assert ("001122334455" in users_text or "00:11:22:33:44:55" in users_text)
    assert 'Tunnel-Private-Group-Id = "10"' in users_text
    assert 'Tunnel-Private-Group-Id = "90"' in users_text
    assert "Tunnel-Type = 13" in users_text
    assert "Tunnel-Medium-Type = 6" in users_text

    clients_text = generate_freeradius_clients_config(test_db)
    assert "client switch_" in clients_text
    assert "192.168.0.10" in clients_text
    assert "client localhost" in clients_text


def test_simulate_radius_auth(test_db):
    """Verify live RADIUS MAB Access-Request simulation logic."""
    dev = Device(
        mac_address="11:22:33:44:55:66",
        hostname="cctv-cam-01",
        device_type="camera",
        approval_status="approved",
        enforcement_status="allowed",
        vlan_id=30,
    )
    test_db.add(dev)
    test_db.commit()

    # 1. Registered approved device -> Steered to VLAN 30
    res = simulate_radius_auth(test_db, "11:22:33:44:55:66")
    assert res["decision"] == "Access-Accept"
    assert res["assigned_vlan"] == 30
    assert res["radius_attributes"]["Tunnel-Private-Group-Id"] == "30"

    # 2. Rogue/unregistered device -> Auto-quarantined to VLAN 90
    rogue_res = simulate_radius_auth(test_db, "FF:EE:DD:CC:BB:AA")
    assert rogue_res["decision"] == "Access-Accept"
    assert rogue_res["assigned_vlan"] == 90
    assert rogue_res["device_registered"] is False


def test_radius_api_endpoints(client, admin_headers, test_db):
    """Verify REST API for reading/updating settings, generating config files, and simulating MAB."""
    dev = Device(
        mac_address="22:33:44:55:66:77",
        hostname="finance-pc",
        device_type="computer",
        approval_status="approved",
        enforcement_status="allowed",
        vlan_id=20,
    )
    test_db.add(dev)
    test_db.commit()

    # 1. GET /radius/settings
    r_get = client.get("/radius/settings", headers=admin_headers)
    assert r_get.status_code == 200
    assert r_get.json()["auth_port"] == 1812

    # 2. POST /radius/settings
    r_post = client.post(
        "/radius/settings",
        headers=admin_headers,
        json={"mab_format": "colon", "quarantine_vlan": 90},
    )
    assert r_post.status_code == 200
    assert r_post.json()["settings"]["mab_format"] == "colon"

    # 3. GET /radius/config/users
    r_users = client.get("/radius/config/users", headers=admin_headers)
    assert r_users.status_code == 200
    assert "Tunnel-Private-Group-Id" in r_users.text

    # 4. GET /radius/config/clients
    r_clients = client.get("/radius/config/clients", headers=admin_headers)
    assert r_clients.status_code == 200
    assert "client localhost" in r_clients.text

    # 5. POST /radius/authenticate (live MAB simulation query)
    r_auth = client.post(
        "/radius/authenticate",
        headers=admin_headers,
        json={"mac_address": "22:33:44:55:66:77"},
    )
    assert r_auth.status_code == 200
    data = r_auth.json()
    assert data["decision"] == "Access-Accept"
    assert data["assigned_vlan"] == 20

    # 6. POST /radius/sync
    r_sync = client.post("/radius/sync", headers=admin_headers)
    assert r_sync.status_code == 200
    assert r_sync.json()["success"] is True
