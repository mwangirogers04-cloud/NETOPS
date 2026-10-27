import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models.switch_config import SwitchConfig
from backend.app.models.switch_backup import SwitchBackup
from backend.app.models.user import User
from backend.app.services.auth_service import create_access_token, hash_password
from backend.app.services.switch_backup_service import (
    generate_config_checksum,
    compute_config_diff,
    detect_security_alerts_in_diff,
)


TEST_DB_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    app.dependency_overrides[get_db] = override_get_db

    db = TestingSessionLocal()
    dev = User(
        username="dev_operator",
        email="dev_operator@example.com",
        hashed_password=hash_password("DevPass@123"),
        role="super_admin",
        is_active=True,
        is_verified=True,
    )
    adm = User(
        username="net_admin",
        email="net_admin@example.com",
        hashed_password=hash_password("AdminPass@123"),
        role="admin",
        is_active=True,
        is_verified=True,
    )
    switch = SwitchConfig(
        vendor="cisco_ios",
        name="Core Switch 1 (Cisco Catalyst)",
        management_ip="192.168.0.2",
        port=22,
        username="admin",
        password="CiscoPassword@123",
        enable_secret="Secret@123",
        model="WS-C2960X-24TS-L",
        is_active=True,
    )
    db.add_all([dev, adm, switch])
    db.commit()
    db.close()

    yield
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


def auth_headers(username: str, role: str) -> dict[str, str]:
    token = create_access_token({"sub": username, "role": role})
    return {"Authorization": f"Bearer {token}"}


def test_diff_engine_detects_changes_and_security_alerts():
    """Verify that compute_config_diff accurately calculates additions, deletions, and security alerts."""
    baseline = (
        "hostname CORE-SWITCH\n"
        "!\n"
        "vlan 10\n"
        " name VOIP_PHONES\n"
        "!\n"
        "interface GigabitEthernet0/1\n"
        " switchport mode access\n"
        " switchport access vlan 10\n"
        "!\n"
        "enable secret 5 $1$mERr$samplehash\n"
        "end\n"
    )

    modified = (
        "hostname CORE-SWITCH\n"
        "!\n"
        "vlan 10\n"
        " name VOIP_PHONES\n"
        "!\n"
        "vlan 99\n"
        " name ROGUE_NETWORK\n"
        "!\n"
        "interface GigabitEthernet0/1\n"
        " switchport mode trunk\n"
        "!\n"
        "enable secret 5 $1$mERr$newsecret999\n"
        "end\n"
    )

    diff_result = compute_config_diff(baseline, modified, "Baseline", "Modified")
    assert diff_result["identical"] is False
    assert diff_result["additions"] > 0
    assert diff_result["deletions"] > 0

    alerts = diff_result["security_alerts"]
    assert any("ROGUE_NETWORK" in a or "VLAN" in a for a in alerts)
    assert any("Trunk" in a for a in alerts)
    assert any("secret" in a or "credentials" in a for a in alerts)


def test_create_switch_backup_api():
    """Admin can trigger an on-demand snapshot backup of switch running-config."""
    headers = auth_headers("net_admin", "admin")

    db = TestingSessionLocal()
    switch = db.query(SwitchConfig).filter(SwitchConfig.name == "Core Switch 1 (Cisco Catalyst)").first()
    switch_id = switch.id
    db.close()

    res = client.post(
        f"/switches/{switch_id}/backups",
        headers=headers,
        json={"backup_name": "Pre-Maintenance Snapshot", "backup_type": "pre-change"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["backup"]["backup_name"] == "Pre-Maintenance Snapshot"
    assert data["backup"]["lines_count"] > 10
    assert data["backup"]["checksum"] is not None
    assert "Baseline" in data["backup"]["change_summary"]

    backup_id = data["backup"]["id"]

    # Retrieve backup detail
    detail_res = client.get(f"/switches/backups/{backup_id}", headers=headers)
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert "hostname" in detail["config_text"].lower()
    assert "vlan" in detail["config_text"].lower()

    # Download configuration file
    download_res = client.get(f"/switches/backups/{backup_id}/download", headers=headers)
    assert download_res.status_code == 200
    assert download_res.headers["content-type"].startswith("text/plain")
    assert "attachment; filename=" in download_res.headers["content-disposition"]


def test_compare_backups_and_live_diff_api():
    """Verify comparing two backups and live vs backup diff."""
    dev_hdr = auth_headers("dev_operator", "super_admin")

    db = TestingSessionLocal()
    switch = db.query(SwitchConfig).first()
    switch_id = switch.id

    b1 = SwitchBackup(
        switch_id=switch_id,
        backup_name="Backup 1",
        config_text="hostname SW1\nvlan 10\n name VOICE\nend\n",
        config_type="running-config",
        backup_type="manual",
        created_by="dev_operator",
        checksum=generate_config_checksum("hostname SW1\nvlan 10\n name VOICE\nend\n"),
        lines_count=4,
        size_bytes=35,
    )
    b2 = SwitchBackup(
        switch_id=switch_id,
        backup_name="Backup 2",
        config_text="hostname SW1\nvlan 10\n name VOICE\nvlan 20\n name DATA\nend\n",
        config_type="running-config",
        backup_type="manual",
        created_by="dev_operator",
        checksum=generate_config_checksum("hostname SW1\nvlan 10\n name VOICE\nvlan 20\n name DATA\nend\n"),
        lines_count=6,
        size_bytes=52,
    )
    db.add_all([b1, b2])
    db.commit()
    b1_id, b2_id = b1.id, b2.id
    db.close()

    # Compare b1 vs b2
    diff_res = client.post(
        "/switches/backups/diff",
        headers=dev_hdr,
        json={"backup_id_a": b1_id, "backup_id_b": b2_id, "compare_with_live": False},
    )
    assert diff_res.status_code == 200
    diff_data = diff_res.json()["diff"]
    assert diff_data["identical"] is False
    assert diff_data["additions"] == 2  # Added vlan 20 and name DATA

    # Compare live switch running config vs b1
    live_diff_res = client.post(
        "/switches/backups/diff",
        headers=dev_hdr,
        json={"backup_id_a": b1_id, "switch_id": switch_id, "compare_with_live": True},
    )
    assert live_diff_res.status_code == 200
    assert "diff_items" in live_diff_res.json()["diff"]


def test_backup_delete_role_restriction():
    """Verify Administrator is forbidden from deleting switch backups (Least Privilege)."""
    adm_hdr = auth_headers("net_admin", "admin")
    dev_hdr = auth_headers("dev_operator", "super_admin")

    db = TestingSessionLocal()
    switch = db.query(SwitchConfig).first()
    b = SwitchBackup(
        switch_id=switch.id,
        backup_name="Audit Backup",
        config_text="hostname SW1\nend\n",
        config_type="running-config",
        backup_type="manual",
        checksum="dummy",
    )
    db.add(b)
    db.commit()
    b_id = b.id
    db.close()

    # Admin CANNOT delete backup (403 Forbidden)
    res_adm = client.delete(f"/switches/backups/{b_id}", headers=adm_hdr)
    assert res_adm.status_code == 403
    assert "super administrator" in res_adm.json()["detail"].lower()

    # Super Admin CAN delete backup (200 OK)
    res_dev = client.delete(f"/switches/backups/{b_id}", headers=dev_hdr)
    assert res_dev.status_code == 200
    assert res_dev.json()["success"] is True

    # Verify record deleted
    db2 = TestingSessionLocal()
    assert db2.get(SwitchBackup, b_id) is None
    db2.close()
