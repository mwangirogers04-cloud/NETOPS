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
