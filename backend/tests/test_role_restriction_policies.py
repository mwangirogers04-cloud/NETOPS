import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models.device import Device
from backend.app.models.event import Event
from backend.app.models.user import User
from backend.app.models.switch_config import SwitchConfig
from backend.app.models.firewall_config import FirewallConfig
from backend.app.models.vlan_config import VlanConfig
from backend.app.models.patch_job import PatchJob
from backend.app.models.access_schedule import AccessSchedule
from backend.app.services.auth_service import create_access_token, hash_password


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
        username="lead_developer",
        email="developer@netops.local",
        phone_number="+254700000001",
        hashed_password=hash_password("DevSecret@123"),
        role="super_admin",
        is_active=True,
        is_verified=True,
    )
    adm1 = User(
        username="net_admin_1",
        email="admin1@netops.local",
        phone_number="+254700000002",
        hashed_password=hash_password("AdminSecret@123"),
        role="admin",
        is_active=True,
        is_verified=True,
    )
    adm2 = User(
        username="net_admin_2",
        email="admin2@netops.local",
        phone_number="+254700000003",
        hashed_password=hash_password("AdminSecret@123"),
        role="admin",
        is_active=True,
        is_verified=True,
    )
    user1 = User(
        username="regular_user",
        email="user@netops.local",
        phone_number="+254700000004",
        hashed_password=hash_password("UserSecret@123"),
        role="user",
        is_active=True,
        is_verified=True,
    )
    db.add_all([dev, adm1, adm2, user1])
    db.commit()
    db.close()

    yield
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


def auth_headers(username: str, role: str):
    token = create_access_token({"sub": username, "role": role})
    return {"Authorization": f"Bearer {token}"}


# -------------------------------------------------------------
# 1. CREATE USER & ROLE ASSIGNMENT RESTRICTIONS
# -------------------------------------------------------------

def test_admin_cannot_create_or_grant_developer_rights():
    admin_hdr = auth_headers("net_admin_1", "admin")
    dev_hdr = auth_headers("lead_developer", "super_admin")

    # A. Administrator CANNOT create a user with Developer rights (403 Forbidden)
    res_dev_by_admin = client.post(
        "/users/",
        headers=admin_hdr,
        json={
            "username": "rogue_dev",
            "email": "rogue_dev@example.com",
            "phone_number": "+254711111111",
            "password": "RogueDev@123",
            "role": "super_admin",
        },
    )
    assert res_dev_by_admin.status_code == 403
    assert "developer" in res_dev_by_admin.json()["detail"].lower() or "super administrator" in res_dev_by_admin.json()["detail"].lower()

    # B. Administrator CAN create a standard user account (201 Created)
    res_user = client.post(
        "/users/",
        headers=admin_hdr,
        json={
            "username": "valid_user",
            "email": "valid@example.com",
            "phone_number": "+254722222222",
            "password": "ValidUser@123",
            "role": "user",
        },
    )
    assert res_user.status_code == 201
    valid_user_id = res_user.json()["user"]["id"]

    # C. Administrator CAN create another administrator account (201 Created)
    res_admin = client.post(
        "/users/",
        headers=admin_hdr,
        json={
            "username": "new_net_admin",
            "email": "new_admin@example.com",
            "phone_number": "+254733333333",
            "password": "NewAdminPass@123",
            "role": "admin",
        },
    )
    assert res_admin.status_code == 201
    assert res_admin.json()["user"]["role"] == "admin"

    # D. Administrator CANNOT give or grant Developer rights to any user (403 Forbidden)
    res_give_dev = client.patch(
        f"/users/{valid_user_id}",
        headers=admin_hdr,
        json={"role": "super_admin"},
    )
    assert res_give_dev.status_code == 403
    assert "developer" in res_give_dev.json()["detail"].lower() or "super administrator" in res_give_dev.json()["detail"].lower()

    # E. Administrator CAN promote a standard user to administrator
    res_promote_admin = client.patch(
        f"/users/{valid_user_id}",
        headers=admin_hdr,
        json={"role": "admin"},
    )
    assert res_promote_admin.status_code == 200
    assert res_promote_admin.json()["user"]["role"] == "admin"

    # F. Administrator CANNOT modify or demote a Developer account (403 Forbidden)
    db = TestingSessionLocal()
    dev_user = db.scalar(select(User).where(User.username == "lead_developer"))
    dev_id = dev_user.id
    db.close()

    res_demote_dev = client.patch(
        f"/users/{dev_id}",
        headers=admin_hdr,
        json={"role": "user"},
    )
    assert res_demote_dev.status_code == 403

    # G. Administrator CANNOT delete an account (only Super Admin / Developer can delete)
    res_delete = client.delete(
        f"/users/{valid_user_id}",
        headers=admin_hdr,
    )
    assert res_delete.status_code == 403
    assert "super administrator" in res_delete.json()["detail"].lower()

    # H. Super Administrator (Developer) CAN create accounts with Developer rights
    res_super_create = client.post(
        "/users/",
        headers=dev_hdr,
        json={
            "username": "second_developer",
            "email": "second_dev@example.com",
            "phone_number": "+254744444444",
            "password": "SecondDevSecret@123",
            "role": "super_admin",
        },
    )
    assert res_super_create.status_code == 201
    assert res_super_create.json()["user"]["role"] == "super_admin"
    second_dev_id = res_super_create.json()["user"]["id"]

    # Super Administrator CAN delete non-developer accounts
    res_del_dev = client.delete(
        f"/users/{valid_user_id}",
        headers=dev_hdr,
    )
    assert res_del_dev.status_code == 200
    assert res_del_dev.json()["status"] == "deleted"

    # Super Administrator accounts are protected against deletion
    res_del_super = client.delete(
        f"/users/{second_dev_id}",
        headers=dev_hdr,
    )
    assert res_del_super.status_code == 403
    assert "super administrator accounts cannot be deleted" in res_del_super.json()["detail"].lower()


# -------------------------------------------------------------
# 2. EDIT CISCO SWITCH & SOPHOS FIREWALL SECRETS
# -------------------------------------------------------------

def test_admin_cannot_edit_switch_or_firewall_secrets():
    admin_hdr = auth_headers("net_admin_1", "admin")
    dev_hdr = auth_headers("lead_developer", "super_admin")

    # A. Cisco Switch secrets locked to Super Admin
    switch_payload = {
        "vendor": "cisco_ios",
        "name": "Distribution Switch 1",
        "management_ip": "192.168.0.254",
        "port": 22,
        "username": "cisco",
        "password": "SwitchSecret@123",
        "enable_secret": "EnableSecret@123",
        "is_active": True,
    }
    # Admin denied saving switch credentials
    res_switch_admin = client.post("/switches/configs", headers=admin_hdr, json=switch_payload)
    assert res_switch_admin.status_code == 403

    # Super Admin allowed saving switch credentials
    res_switch_dev = client.post("/switches/configs", headers=dev_hdr, json=switch_payload)
    assert res_switch_dev.status_code == 200
    cfg_id = res_switch_dev.json()["id"]

    # Admin denied deleting switch profile
    res_del_switch = client.delete(f"/switches/configs/{cfg_id}", headers=admin_hdr)
    assert res_del_switch.status_code == 403

    # Admin denied testing switch connection
    res_test_switch = client.post(
        "/switches/test-connection",
        headers=admin_hdr,
        json={"vendor": "cisco_ios", "management_ip": "192.168.0.254"},
    )
    assert res_test_switch.status_code == 403

    # B. Sophos / Enterprise Firewall secrets locked to Super Admin
    fw_payload = {
        "vendor": "sophos",
        "name": "Primary Sophos XGS",
        "management_url": "https://192.168.0.1:4444",
        "username": "admin",
        "password": "SophosSecret@123",
        "is_active": True,
    }
    # Admin denied saving firewall secrets
    res_fw_admin = client.post("/firewall/config", headers=admin_hdr, json=fw_payload)
    assert res_fw_admin.status_code == 403

    # Super Admin allowed saving firewall secrets
    res_fw_dev = client.post("/firewall/config", headers=dev_hdr, json=fw_payload)
    assert res_fw_dev.status_code == 200

    # Admin denied testing firewall connection
    res_test_fw = client.post("/firewall/test", headers=admin_hdr, json={"vendor": "sophos"})
    assert res_test_fw.status_code == 403


# -------------------------------------------------------------
# 3. PERMANENTLY DELETE DEVICES & RECORDS
# -------------------------------------------------------------

def test_admin_cannot_permanently_delete_devices():
    admin_hdr = auth_headers("net_admin_1", "admin")
    dev_hdr = auth_headers("lead_developer", "super_admin")

    db = TestingSessionLocal()
    dev = Device(
        mac_address="11:22:33:44:55:66",
        ip_address="192.168.0.77",
        hostname="WORKSTATION-77",
        approval_status="approved",
        vlan_id=20,
    )
    db.add(dev)
    db.commit()
    dev_id = dev.id
    db.close()

    # Administrator CANNOT permanently delete device (403 Forbidden)
    res_del_admin = client.delete(f"/devices/{dev_id}", headers=admin_hdr)
    assert res_del_admin.status_code == 403

    # Administrator CANNOT bulk permanently delete devices (403 Forbidden)
    res_bulk_admin = client.post("/devices/bulk-delete", headers=admin_hdr, json={"device_ids": [dev_id]})
    assert res_bulk_admin.status_code == 403

    # Super Administrator CAN permanently delete device
    res_del_dev = client.delete(f"/devices/{dev_id}", headers=dev_hdr)
    assert res_del_dev.status_code == 200
    assert res_del_dev.json()["status"] == "deleted"

    # Verify device record is purged
    db2 = TestingSessionLocal()
    assert db2.get(Device, dev_id) is None
    db2.close()


def test_admin_cannot_delete_vlans_jobs_or_schedules():
    """Verify all delete options (VLANs, patch jobs, access schedules) are denied to Administrators."""
    admin_hdr = auth_headers("net_admin_1", "admin")
    dev_hdr = auth_headers("lead_developer", "super_admin")

    db = TestingSessionLocal()
    # 1. Seed custom VLAN
    vlan = VlanConfig(vlan_id=77, name="Finance_Ops", description="Finance subnet", subnet="192.168.77.0/24")
    db.add(vlan)

    # 2. Seed Patch Job
    job = PatchJob(
        hostname="FINANCE-PC",
        ip_address="192.168.77.10",
        action="INSTALL_ALL_UPDATES",
        status="PENDING",
    )
    db.add(job)

    # 3. Seed Access Schedule
    dev = Device(
        mac_address="22:33:44:55:66:77",
        ip_address="192.168.77.20",
        hostname="FINANCE-TERM",
        approval_status="approved",
        vlan_id=77,
    )
    db.add(dev)
    db.commit()

    schedule = AccessSchedule(
        device_id=dev.id,
        enabled=True,
        days="mon,tue,wed,thu,fri",
        start_time=datetime.strptime("08:00", "%H:%M").time(),
        end_time=datetime.strptime("17:00", "%H:%M").time(),
    )
    db.add(schedule)
    db.commit()

    vlan_id = vlan.vlan_id
    job_id = job.id
    sched_id = schedule.id
    db.close()

    # --- A. VLAN Deletion ---
    # Administrator CANNOT delete VLAN (403 Forbidden)
    res_vlan_admin = client.delete(f"/switches/vlans/{vlan_id}", headers=admin_hdr)
    assert res_vlan_admin.status_code == 403
    assert "super administrator" in res_vlan_admin.json()["detail"].lower()

    # Super Administrator CAN delete VLAN
    res_vlan_dev = client.delete(f"/switches/vlans/{vlan_id}", headers=dev_hdr)
    assert res_vlan_dev.status_code == 200

    # --- B. Patch Job Deletion ---
    # Administrator CANNOT delete patch job (403 Forbidden)
    res_job_admin = client.delete(f"/endpoint-updates/jobs/{job_id}", headers=admin_hdr)
    assert res_job_admin.status_code == 403
    assert "super administrator" in res_job_admin.json()["detail"].lower()

    # Super Administrator CAN delete patch job
    res_job_dev = client.delete(f"/endpoint-updates/jobs/{job_id}", headers=dev_hdr)
    assert res_job_dev.status_code == 200

    # --- C. Access Schedule Deletion ---
    # Administrator CANNOT delete access schedule (403 Forbidden)
    res_sched_admin = client.delete(f"/access-schedules/{sched_id}", headers=admin_hdr)
    assert res_sched_admin.status_code == 403
    assert "super administrator" in res_sched_admin.json()["detail"].lower()

    # Super Administrator CAN delete access schedule
    res_sched_dev = client.delete(f"/access-schedules/{sched_id}", headers=dev_hdr)
    assert res_sched_dev.status_code == 200


# -------------------------------------------------------------
# 4. CLEAR AUDIT LOGS & EVENT HISTORY
# -------------------------------------------------------------

def test_admin_cannot_clear_audit_logs():
    admin_hdr = auth_headers("net_admin_1", "admin")
    dev_hdr = auth_headers("lead_developer", "super_admin")

    db = TestingSessionLocal()
    ev1 = Event(event_type="security_alert", message="Unauthorized access attempt", actor="net_admin_1")
    ev2 = Event(event_type="vlan_change", message="Port changed to VLAN 20", actor="net_admin_1")
    db.add_all([ev1, ev2])
    db.commit()
    ev_id = ev1.id
    db.close()

    # Administrator CANNOT clear event history (403 Forbidden)
    res_clear_admin = client.delete("/events/clear", headers=admin_hdr)
    assert res_clear_admin.status_code == 403

    # Administrator CANNOT delete individual audit event (403 Forbidden)
    res_del_admin = client.delete(f"/events/{ev_id}", headers=admin_hdr)
    assert res_del_admin.status_code == 403

    # Super Administrator CAN clear event history
    res_clear_dev = client.delete("/events/clear", headers=dev_hdr)
    assert res_clear_dev.status_code == 200
    assert res_clear_dev.json()["status"] == "cleared"

    db2 = TestingSessionLocal()
    assert len(db2.scalars(select(Event)).all()) == 0
    db2.close()


# -------------------------------------------------------------
# 5. BYPASS PASSWORD EXPIRATION / LOCKOUTS
# -------------------------------------------------------------

def test_admin_cannot_bypass_lockouts_or_reset_admin_passwords():
    admin_hdr = auth_headers("net_admin_1", "admin")
    dev_hdr = auth_headers("lead_developer", "super_admin")

    # A. Administrator CANNOT reset another Administrator's password / clear their lockout
    res_reset_adm = client.post(
        "/auth/forgot-password/admin-reset",
        headers=admin_hdr,
        json={
            "target_identifier": "net_admin_2",
            "new_password": "NewAdminPass@999",
        },
    )
    assert res_reset_adm.status_code == 403
    assert "administrator cannot reset passwords or bypass lockouts for administrator accounts" in res_reset_adm.json()["detail"].lower()

    # B. Administrator CANNOT reset the Super Administrator password / clear their lockout
    res_reset_super = client.post(
        "/auth/forgot-password/admin-reset",
        headers=admin_hdr,
        json={
            "target_identifier": "lead_developer",
            "new_password": "HackedDevPass@999",
        },
    )
    assert res_reset_super.status_code == 403
    assert "administrator cannot reset the password" in res_reset_super.json()["detail"].lower()

    # C. Administrator CAN directly reset a standard user's password
    res_reset_user = client.post(
        "/auth/forgot-password/admin-reset",
        headers=admin_hdr,
        json={
            "target_identifier": "regular_user",
            "new_password": "UserNewPass@888",
        },
    )
    assert res_reset_user.status_code == 200
    assert res_reset_user.json()["status"] == "password_reset_success"

    # D. Super Administrator CAN directly reset an Administrator's password / clear their lockout
    res_dev_reset_adm = client.post(
        "/auth/forgot-password/admin-reset",
        headers=dev_hdr,
        json={
            "target_identifier": "net_admin_2",
            "new_password": "DevResetAdmin@777",
        },
    )
    assert res_dev_reset_adm.status_code == 200
    assert res_dev_reset_adm.json()["reset_by_role"] == "super_admin"
