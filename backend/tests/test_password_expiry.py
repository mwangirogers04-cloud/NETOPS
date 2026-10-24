from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models.user import User
from backend.app.api.auth import (
    clear_failed_login_attempts,
    is_password_expired,
    get_password_expiry_info,
)
from backend.app.services.auth_service import hash_password, create_access_token


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
    clear_failed_login_attempts()
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        clear_failed_login_attempts()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.pop(get_db, None)


def test_developer_password_does_not_expire_after_three_months(client, db_session):
    """
    Developers ('super_admin') are exempt from password expiration:
    Even after 4 months (120 days), developer passwords never expire and can sign in.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    four_months_ago = now - timedelta(days=120)

    dev = User(
        username="dev_senior",
        email="dev_senior@netops.local",
        phone_number="+254700000001",
        hashed_password=hash_password("DevSenior@2026!"),
        role="super_admin",
        is_active=True,
        is_verified=True,
        password_changed_at=four_months_ago,
        created_at=four_months_ago,
    )
    db_session.add(dev)
    db_session.commit()

    # Model and helper assertions
    assert is_password_expired(dev) is False
    info = get_password_expiry_info(dev)
    assert info["expires"] is False
    assert info["is_expired"] is False
    assert "Developer passwords do not expire" in info["message"]

    # Login attempt succeeds
    res = client.post("/auth/login", json={"username": "dev_senior", "password": "DevSenior@2026!"})
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["user"]["role"] == "super_admin"
    assert data["user"]["password_expiry"]["expires"] is False


def test_admin_password_expires_after_three_months_and_admin_can_reset_own_password(client, db_session):
    """
    Administrator ('admin') passwords expire after 3 months (90 days).
    When expired, login prompts them to reset, and the admin can reset their password
    using the change-expired-password endpoint.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    expired_date = now - timedelta(days=95)

    admin = User(
        username="netops_admin",
        email="netops_admin@netops.local",
        phone_number="+254711111102",
        hashed_password=hash_password("OldAdminPass@2026!"),
        role="admin",
        is_active=True,
        is_verified=True,
        password_changed_at=expired_date,
        created_at=expired_date,
    )
    db_session.add(admin)
    db_session.commit()

    assert is_password_expired(admin) is True
    info = get_password_expiry_info(admin)
    assert info["is_expired"] is True
    assert info["can_self_reset"] is True

    # 1. Login attempt with expired password is rejected with 403 and admin expiry header
    res = client.post("/auth/login", json={"username": "netops_admin", "password": "OldAdminPass@2026!"})
    assert res.status_code == 403
    assert "Your Administrator password has expired after 3 months" in res.json()["detail"]
    assert res.headers.get("x-password-expired") == "admin"

    # 2. Admin resets their expired password
    reset_res = client.post(
        "/auth/change-expired-password",
        json={
            "identifier": "netops_admin",
            "current_password": "OldAdminPass@2026!",
            "new_password": "NewAdminPass@2026!",
        },
    )
    assert reset_res.status_code == 200
    reset_data = reset_res.json()
    assert reset_data["status"] == "password_reset_success"
    assert "access_token" in reset_data

    # 3. Database record is refreshed
    db_session.refresh(admin)
    assert (now - admin.password_changed_at).total_seconds() < 10
    assert is_password_expired(admin) is False

    # 4. Admin can now log in normally with new password
    res_login = client.post("/auth/login", json={"username": "netops_admin", "password": "NewAdminPass@2026!"})
    assert res_login.status_code == 200


def test_standard_user_password_expires_and_requires_contacting_admin(client, db_session):
    """
    Standard users ('user') passwords expire after 3 months (90 days).
    When expired, they cannot log in and are instructed to contact an Administrator or Developer.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    expired_date = now - timedelta(days=92)

    user = User(
        username="standard_alice",
        email="alice@netops.local",
        phone_number="+254722222203",
        hashed_password=hash_password("AlicePass@2026!"),
        role="user",
        is_active=True,
        is_verified=True,
        password_changed_at=expired_date,
        created_at=expired_date,
    )
    db_session.add(user)
    db_session.commit()

    assert is_password_expired(user) is True
    info = get_password_expiry_info(user)
    assert info["is_expired"] is True
    assert info["can_self_reset"] is False

    # 1. Login attempt blocked with 403 instructing to contact admin/developer
    res = client.post("/auth/login", json={"username": "standard_alice", "password": "AlicePass@2026!"})
    assert res.status_code == 403
    detail = res.json()["detail"]
    assert "Your password has expired after 3 months" in detail
    assert "Standard users are required to contact the Administrator or Developer to reset the password." in detail
    assert res.headers.get("x-password-expired") == "user"

    # 2. Standard user cannot self-reset via change-expired-password endpoint
    self_reset_res = client.post(
        "/auth/change-expired-password",
        json={
            "identifier": "standard_alice",
            "current_password": "AlicePass@2026!",
            "new_password": "NewAlicePass@2026!",
        },
    )
    assert self_reset_res.status_code == 403
    assert "Standard users cannot reset their own password" in self_reset_res.json()["detail"]


def test_admin_can_reset_expired_standard_user_password(client, db_session):
    """
    When a standard user's password has expired, an Administrator or Developer can directly reset it,
    refreshing password_changed_at and allowing the standard user to log in again.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    expired_date = now - timedelta(days=100)

    admin = User(
        username="supervisor_admin",
        email="supervisor@netops.local",
        phone_number="+254733333304",
        hashed_password=hash_password("Supervisor@2026!"),
        role="admin",
        is_active=True,
        is_verified=True,
        password_changed_at=now,
        created_at=now,
    )
    bob = User(
        username="standard_bob",
        email="bob@netops.local",
        phone_number="+254744444405",
        hashed_password=hash_password("BobOldPass@2026!"),
        role="user",
        is_active=True,
        is_verified=True,
        password_changed_at=expired_date,
        created_at=expired_date,
    )
    db_session.add_all([admin, bob])
    db_session.commit()

    # Admin authorizes direct reset for Bob without OTP
    admin_token = create_access_token({"sub": admin.username, "role": admin.role, "user_id": admin.id})
    reset_res = client.post(
        "/auth/admin-reset-password",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "target_identifier": "standard_bob",
            "new_password": "BobNewPass@2026!",
        },
    )
    assert reset_res.status_code == 200

    # Bob's password_changed_at is updated
    db_session.refresh(bob)
    assert (now - bob.password_changed_at).total_seconds() < 10
    assert is_password_expired(bob) is False

    # Bob can now log in
    res_login = client.post("/auth/login", json={"username": "standard_bob", "password": "BobNewPass@2026!"})
    assert res_login.status_code == 200
    assert res_login.json()["user"]["username"] == "standard_bob"


def test_authenticated_change_password(client, db_session):
    """
    An authenticated user with a valid session can change their password.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    user = User(
        username="carol_user",
        email="carol@netops.local",
        phone_number="+254755555506",
        hashed_password=hash_password("CarolPass@2026!"),
        role="user",
        is_active=True,
        is_verified=True,
        password_changed_at=now - timedelta(days=30),  # 30 days old, not expired
        created_at=now - timedelta(days=30),
    )
    db_session.add(user)
    db_session.commit()

    token = create_access_token({"sub": user.username, "role": user.role, "user_id": user.id})

    # Wrong current password fails
    bad_res = client.post(
        "/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "current_password": "WrongPassword123!",
            "new_password": "CarolBrandNew@2026!",
        },
    )
    assert bad_res.status_code == 400
    assert "Current password is incorrect" in bad_res.json()["detail"]

    # Same password rejected
    same_res = client.post(
        "/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "current_password": "CarolPass@2026!",
            "new_password": "CarolPass@2026!",
        },
    )
    assert same_res.status_code == 400
    assert "New password must be different" in same_res.json()["detail"]

    # Successful change
    good_res = client.post(
        "/auth/change-password",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "current_password": "CarolPass@2026!",
            "new_password": "CarolBrandNew@2026!",
        },
    )
    assert good_res.status_code == 200
    assert good_res.json()["status"] == "success"

    # User's password_changed_at is refreshed
    db_session.refresh(user)
    assert (datetime.now(timezone.utc).replace(tzinfo=None) - user.password_changed_at).total_seconds() < 10


def test_users_api_returns_password_expiry_metadata(client, db_session):
    """
    GET /users includes password_expiry details (is_expired, days_remaining, policy).
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    admin = User(
        username="director_admin",
        email="director@netops.local",
        phone_number="+254766666607",
        hashed_password=hash_password("Director@2026!"),
        role="admin",
        is_active=True,
        is_verified=True,
        password_changed_at=now,
        created_at=now,
    )
    db_session.add(admin)
    db_session.commit()

    token = create_access_token({"sub": admin.username, "role": admin.role, "user_id": admin.id})
    res = client.get("/users/", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    users = res.json()
    assert len(users) >= 1
    admin_item = next(u for u in users if u["username"] == "director_admin")
    assert "password_expiry" in admin_item
    assert admin_item["password_expiry"]["expires"] is True
    assert admin_item["password_expiry"]["is_expired"] is False
    assert admin_item["password_expiry"]["days_remaining"] >= 89
