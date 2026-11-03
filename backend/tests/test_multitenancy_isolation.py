import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.main import app
from backend.app.models.device import Device
from backend.app.models.user import User
from backend.app.services.auth_service import create_access_token, hash_password


client = TestClient(app)


def test_probe_script_download():
    """Verify that clients can download the netops_probe.py script without auth."""
    res = client.get("/discovery/probe-script")
    assert res.status_code == 200
    assert "NETOPS Remote LAN Scanner Probe" in res.text
    assert "Content-Disposition" in res.headers
    assert "netops_probe.py" in res.headers["Content-Disposition"]


def test_unauthenticated_device_access():
    """Unauthenticated requests must not receive any devices."""
    res = client.get("/devices/")
    assert res.status_code == 200
    assert res.json() == []


def test_user_device_isolation():
    """Verify that non-super-admin users only receive devices they own."""
    from backend.app.database import SessionLocal

    db: Session = SessionLocal()
    try:
        # Create user A
        user_a = db.query(User).filter(User.username == "test_tenant_a").first()
        if not user_a:
            user_a = User(
                username="test_tenant_a",
                email="tenant_a@example.com",
                hashed_password=hash_password("Password123!"),
                role="user",
                is_active=True,
            )
            db.add(user_a)
            db.commit()
            db.refresh(user_a)

        # Create user B
        user_b = db.query(User).filter(User.username == "test_tenant_b").first()
        if not user_b:
            user_b = User(
                username="test_tenant_b",
                email="tenant_b@example.com",
                hashed_password=hash_password("Password123!"),
                role="user",
                is_active=True,
            )
            db.add(user_b)
            db.commit()
            db.refresh(user_b)

        # Add a device for Tenant A
        dev_a = db.query(Device).filter(Device.mac_address == "00:AA:AA:AA:AA:AA").first()
        if not dev_a:
            dev_a = Device(
                mac_address="00:AA:AA:AA:AA:AA",
                ip_address="10.0.0.50",
                hostname="Tenant-A-Laptop",
                owner_id=user_a.id,
                status="online",
            )
            db.add(dev_a)
            db.commit()

        # Add a device for Tenant B
        dev_b = db.query(Device).filter(Device.mac_address == "00:BB:BB:BB:BB:BB").first()
        if not dev_b:
            dev_b = Device(
                mac_address="00:BB:BB:BB:BB:BB",
                ip_address="10.1.0.70",
                hostname="Tenant-B-Phone",
                owner_id=user_b.id,
                status="online",
            )
            db.add(dev_b)
            db.commit()

        # Token for A
        token_a = create_access_token({"sub": user_a.username, "role": user_a.role, "id": user_a.id})
        # Token for B
        token_b = create_access_token({"sub": user_b.username, "role": user_b.role, "id": user_b.id})

        # Check A's devices
        res_a = client.get("/devices/", headers={"Authorization": f"Bearer {token_a}"})
        assert res_a.status_code == 200
        a_devices = res_a.json()
        assert all(d["owner_id"] == user_a.id for d in a_devices)
        assert any(d["mac_address"] == "00:AA:AA:AA:AA:AA" for d in a_devices)
        assert not any(d["mac_address"] == "00:BB:BB:BB:BB:BB" for d in a_devices)

        # Check B's devices
        res_b = client.get("/devices/", headers={"Authorization": f"Bearer {token_b}"})
        assert res_b.status_code == 200
        b_devices = res_b.json()
        assert all(d["owner_id"] == user_b.id for d in b_devices)
        assert any(d["mac_address"] == "00:BB:BB:BB:BB:BB" for d in b_devices)
        assert not any(d["mac_address"] == "00:AA:AA:AA:AA:AA" for d in b_devices)

        # Clean up test devices
        db.query(Device).filter(Device.mac_address.in_(["00:AA:AA:AA:AA:AA", "00:BB:BB:BB:BB:BB"])).delete()
        db.query(User).filter(User.username.in_(["test_tenant_a", "test_tenant_b"])).delete()
        db.commit()

    finally:
        db.close()


def test_admin_device_visibility():
    """Verify that users with role='admin' can view network infrastructure devices."""
    from backend.app.database import SessionLocal

    db: Session = SessionLocal()
    try:
        admin_user = db.query(User).filter(User.role == "admin").first()
        if not admin_user:
            admin_user = User(
                username="test_admin_role",
                email="admin_role@example.com",
                hashed_password=hash_password("Password123!"),
                role="admin",
                is_active=True,
            )
            db.add(admin_user)
            db.commit()
            db.refresh(admin_user)

        token = create_access_token({"sub": admin_user.username, "role": admin_user.role, "id": admin_user.id})
        res = client.get("/devices/", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200
        devices = res.json()
        assert len(devices) > 0
    finally:
        db.close()

