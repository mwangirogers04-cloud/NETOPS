import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models.user import PasswordResetOTP, User
from backend.app.services.auth_service import (
    hash_password,
    seed_default_users,
    create_access_token,
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
    db = TestingSessionLocal()
    seed_default_users(db)
    db.close()
    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=engine)


def test_seed_default_users():
    db = TestingSessionLocal()
    dev = db.query(User).filter(User.username == "developer").first()
    adm = db.query(User).filter(User.username == "admin").first()
    db.close()

    assert dev is not None
    assert dev.role == "super_admin"
    assert dev.email == "developer@netops.local"

    assert adm is not None
    assert adm.role == "admin"


def test_login_successful():
    res = client.post(
        "/auth/login",
        json={"username": "developer", "password": "Admin@1234"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["user"]["role"] == "super_admin"
    assert data["user"]["username"] == "developer"


def test_login_invalid_password():
    res = client.post(
        "/auth/login",
        json={"username": "developer", "password": "WrongPassword"},
    )
    assert res.status_code == 401
    assert "Incorrect" in res.json()["detail"]


def test_create_user_and_activation_link():
    # Login as admin to get token
    login_res = client.post(
        "/auth/login",
        json={"username": "admin", "password": "Admin@1234"},
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    create_res = client.post(
        "/users/",
        headers=headers,
        json={
            "username": "john_doe",
            "email": "john@example.com",
            "phone_number": "+254712345678",
            "password": "Password@123",
            "role": "user",
        },
    )
    assert create_res.status_code == 201
    created_data = create_res.json()
    assert created_data["status"] == "created"
    assert "activation_link" in created_data
    assert "activation_token=" in created_data["activation_link"]

    # Verify user was created in DB and is not verified yet
    db = TestingSessionLocal()
    u = db.query(User).filter(User.username == "john_doe").first()
    assert u is not None
    assert u.is_verified is False
    activation_token = u.activation_token
    db.close()

    # User clicks activation link
    act_res = client.post(
        "/auth/activate",
        json={"activation_token": activation_token},
    )
    assert act_res.status_code == 200
    assert act_res.json()["status"] == "activated"

    # User can now login with the credentials given by admin
    user_login = client.post(
        "/auth/login",
        json={"username": "john_doe", "password": "Password@123"},
    )
    assert user_login.status_code == 200
    assert user_login.json()["user"]["role"] == "user"


def test_forgot_password_otp_and_reset():
    # 1. Request channels
    ch_res = client.post(
        "/auth/forgot-password/channels",
        json={"identifier": "developer"},
    )
    assert ch_res.status_code == 200
    ch_data = ch_res.json()
    assert ch_data["has_email"] is True
    assert ch_data["has_phone"] is True

    # 2. Send 5-minute OTP via email
    otp_res = client.post(
        "/auth/forgot-password/send-otp",
        json={"identifier": "developer", "channel": "email"},
    )
    assert otp_res.status_code == 200
    otp_data = otp_res.json()
    assert otp_data["status"] == "otp_sent"
    assert otp_data["expires_in_minutes"] == 5
    otp_code = otp_data["dev_otp_preview"]
    assert len(otp_code) == 6

    # 3. Reset password with OTP
    reset_res = client.post(
        "/auth/forgot-password/reset",
        json={
            "identifier": "developer",
            "otp_code": otp_code,
            "new_password": "NewDeveloperPassword@999",
        },
    )
    assert reset_res.status_code == 200
    assert reset_res.json()["status"] == "password_reset_success"

    # 4. Verify login with new password succeeds
    login_new = client.post(
        "/auth/login",
        json={"username": "developer", "password": "NewDeveloperPassword@999"},
    )
    assert login_new.status_code == 200

    # 5. Verify old password fails
    login_old = client.post(
        "/auth/login",
        json={"username": "developer", "password": "Admin@1234"},
    )
    assert login_old.status_code == 401


def test_expired_otp_rejected():
    # Generate OTP
    otp_res = client.post(
        "/auth/forgot-password/send-otp",
        json={"identifier": "developer", "channel": "email"},
    )
    otp_code = otp_res.json()["dev_otp_preview"]

    # Artificially expire the OTP in the DB to test the 5-minute rule
    db = TestingSessionLocal()
    dev = db.query(User).filter(User.username == "developer").first()
    otp_rec = db.query(PasswordResetOTP).filter(
        PasswordResetOTP.user_id == dev.id,
        PasswordResetOTP.otp_code == otp_code,
    ).first()
    otp_rec.expires_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=10)
    db.commit()
    db.close()

    # Attempt reset with expired OTP
    reset_res = client.post(
        "/auth/forgot-password/reset",
        json={
            "identifier": "developer",
            "otp_code": otp_code,
            "new_password": "BrandNewPassword@123",
        },
    )
    assert reset_res.status_code == 400
    assert "expired" in reset_res.json()["detail"].lower()


def test_admin_update_user_details():
    # Login as admin
    login_adm = client.post("/auth/login", json={"username": "admin", "password": "Admin@1234"})
    token = login_adm.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create user
    create_res = client.post(
        "/users/",
        headers=headers,
        json={
            "username": "alice_test",
            "email": "alice@example.com",
            "phone_number": "+254711223344",
            "password": "Password@123",
            "role": "user",
        },
    )
    user_id = create_res.json()["user"]["id"]

    # Update user details
    patch_res = client.patch(
        f"/users/{user_id}",
        headers=headers,
        json={
            "username": "alice_updated",
            "email": "alice_new@example.com",
            "phone_number": "+254799887766",
            "password": "NewAlicePassword@456",
        },
    )
    assert patch_res.status_code == 200
    data = patch_res.json()
    assert data["status"] == "updated"
    assert data["user"]["username"] == "alice_updated"
    assert data["user"]["email"] == "alice_new@example.com"
    assert data["user"]["phone_number"] == "+254799887766"

    # Verify login with new password works
    login_alice = client.post(
        "/auth/login",
        json={"username": "alice_updated", "password": "NewAlicePassword@456"},
    )
    assert login_alice.status_code == 200


def test_update_user_duplicate_username_rejected():
    login_adm = client.post("/auth/login", json={"username": "admin", "password": "Admin@1234"})
    token = login_adm.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create user
    create_res = client.post(
        "/users/",
        headers=headers,
        json={
            "username": "bob_test",
            "email": "bob@example.com",
            "phone_number": "+254755667788",
            "password": "Password@123",
            "role": "user",
        },
    )
    user_id = create_res.json()["user"]["id"]

    # Attempt to change username to existing 'admin'
    patch_res = client.patch(
        f"/users/{user_id}",
        headers=headers,
        json={"username": "admin"},
    )
    assert patch_res.status_code == 400
    assert "already taken" in patch_res.json()["detail"].lower()


def test_admin_cannot_edit_super_admin():
    login_adm = client.post("/auth/login", json={"username": "admin", "password": "Admin@1234"})
    token = login_adm.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    db = TestingSessionLocal()
    dev = db.query(User).filter(User.username == "developer").first()
    dev_id = dev.id
    db.close()

    # Admin attempts to edit super_admin account
    patch_res = client.patch(
        f"/users/{dev_id}",
        headers=headers,
        json={"username": "developer_hacked"},
    )
    assert patch_res.status_code == 403
    assert "only super administrators" in patch_res.json()["detail"].lower()


def test_super_admin_can_update_roles():
    login_dev = client.post("/auth/login", json={"username": "developer", "password": "Admin@1234"})
    token = login_dev.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create standard user
    create_res = client.post(
        "/users/",
        headers=headers,
        json={
            "username": "charlie_test",
            "email": "charlie@example.com",
            "phone_number": "+254722334455",
            "password": "Password@123",
            "role": "user",
        },
    )
    user_id = create_res.json()["user"]["id"]

    # Promote to admin
    patch_res = client.patch(
        f"/users/{user_id}",
        headers=headers,
        json={"role": "admin"},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["user"]["role"] == "admin"


def test_duplicate_email_and_phone_registration_prompts():
    # First register a new user via /auth/register
    reg_res = client.post(
        "/auth/register",
        json={
            "username": "first_user",
            "email": "unique_user@example.com",
            "phone_number": "+254712345678",
            "password": "Password@123",
        },
    )
    assert reg_res.status_code == 201
    assert reg_res.json()["status"] == "registered"

    # Attempt to register another account with the SAME email (case-insensitive)
    dup_email_res = client.post(
        "/auth/register",
        json={
            "username": "second_user",
            "email": "UNIQUE_USER@example.com",
            "phone_number": "+254799999999",
            "password": "Password@123",
        },
    )
    assert dup_email_res.status_code == 400
    assert dup_email_res.json()["detail"] == "The email address already exists, please try another email address."

    # Attempt to register another account with the SAME phone number (even in local 07... format)
    dup_phone_res = client.post(
        "/auth/register",
        json={
            "username": "third_user",
            "email": "third_user@example.com",
            "phone_number": "0712 345 678",
            "password": "Password@123",
        },
    )
    assert dup_phone_res.status_code == 400
    assert dup_phone_res.json()["detail"] == "The phone number already exists, please try another number."

    # Verify /auth/check-availability endpoint returns exact conflict prompts
    avail_res = client.post(
        "/auth/check-availability",
        json={
            "email": "unique_user@example.com",
            "phone_number": "0712345678",
        },
    )
    assert avail_res.status_code == 200
    avail_data = avail_res.json()
    assert avail_data["available"] is False
    assert avail_data["conflicts"]["email"] == "The email address already exists, please try another email address."
    assert avail_data["conflicts"]["phone_number"] == "The phone number already exists, please try another number."

    # Verify admin /users/ create endpoint also enforces phone & email uniqueness
    login_adm = client.post("/auth/login", json={"username": "admin", "password": "Admin@1234"})
    headers = {"Authorization": f"Bearer {login_adm.json()['access_token']}"}

    adm_dup_phone = client.post(
        "/users/",
        headers=headers,
        json={
            "username": "admin_created_dup",
            "email": "fresh_email@example.com",
            "phone_number": "+254712345678",
            "password": "Password@123",
            "role": "user",
        },
    )
    assert adm_dup_phone.status_code == 400
    assert adm_dup_phone.json()["detail"] == "The phone number already exists, please try another number."


def test_admin_and_developer_direct_password_reset_without_otp():
    # Register a standard user
    reg_res = client.post(
        "/auth/register",
        json={
            "username": "staff_member",
            "email": "staff@example.com",
            "phone_number": "+254744556677",
            "password": "OldPassword@123",
        },
    )
    assert reg_res.status_code == 201

    # 1. Standard user cannot authorize a direct password reset without OTP
    denied_res = client.post(
        "/auth/forgot-password/admin-reset",
        json={
            "target_identifier": "staff_member",
            "admin_identifier": "staff_member",
            "admin_password": "OldPassword@123",
            "new_password": "HackedPassword@123",
        },
    )
    assert denied_res.status_code == 403
    assert "administrative or developer rights" in denied_res.json()["detail"].lower()

    # 2. Administrator directly resets staff_member's password on Login Page (no OTP required)
    adm_reset_res = client.post(
        "/auth/forgot-password/admin-reset",
        json={
            "target_identifier": "staff@example.com",
            "admin_identifier": "admin",
            "admin_password": "Admin@1234",
            "new_password": "ResetByAdmin@456",
        },
    )
    assert adm_reset_res.status_code == 200
    assert adm_reset_res.json()["status"] == "password_reset_success"
    assert adm_reset_res.json()["username"] == "staff_member"
    assert adm_reset_res.json()["reset_by"] == "admin"

    # Verify staff_member can log in with the new password immediately
    login_staff = client.post(
        "/auth/login",
        json={"username": "staff_member", "password": "ResetByAdmin@456"},
    )
    assert login_staff.status_code == 200

    # 3. Administrator cannot reset Developer (super_admin) password
    adm_vs_dev = client.post(
        "/auth/forgot-password/admin-reset",
        json={
            "target_identifier": "developer",
            "admin_identifier": "admin",
            "admin_password": "Admin@1234",
            "new_password": "TryResetDev@123",
        },
    )
    assert adm_vs_dev.status_code == 403
    assert "only a developer" in adm_vs_dev.json()["detail"].lower()

    # 4. Developer (super_admin) can directly reset any account (even by phone number)
    dev_reset_res = client.post(
        "/auth/forgot-password/admin-reset",
        json={
            "target_identifier": "0744556677",
            "admin_identifier": "developer",
            "admin_password": "Admin@1234",
            "new_password": "ResetByDeveloper@789",
        },
    )
    assert dev_reset_res.status_code == 200
    assert dev_reset_res.json()["reset_by"] == "developer"
    assert dev_reset_res.json()["reset_by_role"] == "super_admin"

    login_staff_2 = client.post(
        "/auth/login",
        json={"username": "staff_member", "password": "ResetByDeveloper@789"},
    )
    assert login_staff_2.status_code == 200



