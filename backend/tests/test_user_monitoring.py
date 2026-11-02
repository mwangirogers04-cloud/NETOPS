from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models.user import User, UserSession
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
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
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


def test_user_monitoring_endpoints(client, db_session):
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    # 1. Create a super_admin user (developer) and a regular user
    admin_user = User(
        username="dev_monitor",
        email="dev_monitor@netops.local",
        hashed_password=hash_password("DevPass123!"),
        role="super_admin",
        is_verified=True,
        is_active=True,
        created_at=now - timedelta(days=5),
    )
    regular_user = User(
        username="john_doe",
        email="john@example.com",
        hashed_password=hash_password("JohnPass123!"),
        role="user",
        is_verified=True,
        is_active=True,
        created_at=now - timedelta(days=2),
    )
    db_session.add_all([admin_user, regular_user])
    db_session.commit()
    db_session.refresh(admin_user)
    db_session.refresh(regular_user)

    admin_token = create_access_token({"sub": admin_user.username, "role": admin_user.role})
    user_token = create_access_token({"sub": regular_user.username, "role": regular_user.role})

    # 2. Add an active session for regular_user (online now)
    session1 = UserSession(
        user_id=regular_user.id,
        username=regular_user.username,
        role=regular_user.role,
        ip_address="197.232.40.10",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36",
        current_page="devices",
        login_at=now - timedelta(minutes=15),
        last_activity_at=now - timedelta(seconds=20),
        duration_seconds=900,
        is_active=True,
    )
    # 3. Add an older, closed session for admin
    session2 = UserSession(
        user_id=admin_user.id,
        username=admin_user.username,
        role=admin_user.role,
        ip_address="102.220.12.94",
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.0",
        current_page="settings",
        login_at=now - timedelta(days=1),
        logout_at=now - timedelta(days=1) + timedelta(minutes=45),
        last_activity_at=now - timedelta(days=1) + timedelta(minutes=45),
        duration_seconds=2700,
        is_active=False,
    )
    db_session.add_all([session1, session2])
    db_session.commit()

    headers = {"Authorization": f"Bearer {admin_token}"}

    # 4. Test Summary endpoint
    res = client.get("/user-monitoring/summary", headers=headers)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["total_registered_users"] == 2
    assert data["online_users_count"] == 1
    assert data["total_sessions_all_time"] == 2

    # 5. Test Live Sessions endpoint
    res = client.get("/user-monitoring/live-sessions", headers=headers)
    assert res.status_code == 200
    live = res.json()
    assert len(live) == 1
    assert live[0]["username"] == "john_doe"
    assert live[0]["current_page"] == "devices"
    assert live[0]["ip_address"] == "197.232.40.10"
    assert live[0]["is_online"] is True
    assert live[0]["device"]["browser"] == "Chrome 131"
    assert live[0]["device"]["os"] == "Windows 10/11"
    assert "location" in live[0]
    assert live[0]["location_display"] is not None

    # 6. Test Users Lifecycle Overview
    res = client.get("/user-monitoring/users-overview", headers=headers)
    assert res.status_code == 200
    users_overview = res.json()
    assert len(users_overview) == 2
    
    # john_doe is online
    john_info = next(u for u in users_overview if u["username"] == "john_doe")
    assert john_info["is_online"] is True
    assert john_info["first_seen"] is not None
    assert john_info["last_seen"] is not None
    assert john_info["last_ip"] == "197.232.40.10"
    assert "last_location" in john_info
    assert john_info["last_location_display"] is not None
    assert john_info["total_sessions"] == 1

    # 7. Test Sessions History
    res = client.get("/user-monitoring/sessions-history?status_filter=all", headers=headers)
    assert res.status_code == 200
    history = res.json()
    assert history["total"] == 2
    assert len(history["items"]) == 2

    # 8. Test Terminate Session
    res = client.post(f"/user-monitoring/terminate-session/{session1.id}", headers=headers)
    assert res.status_code == 200

    # Verify session is now terminated
    res = client.get("/user-monitoring/live-sessions", headers=headers)
    assert len(res.json()) == 0

    # 9. Verify regular users cannot access monitoring endpoints (403 forbidden)
    user_headers = {"Authorization": f"Bearer {user_token}"}
    res = client.get("/user-monitoring/summary", headers=user_headers)
    assert res.status_code == 403


def test_heartbeat_updates_current_page_and_ip(client, db_session):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    user = User(
        username="nav_user",
        email="nav@example.com",
        hashed_password=hash_password("NavPass123!"),
        role="user",
        is_verified=True,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_access_token({"sub": user.username, "role": user.role})

    # Create active session
    session = UserSession(
        user_id=user.id,
        username=user.username,
        role=user.role,
        ip_address="127.0.0.1",
        user_agent="Firefox",
        current_page="dashboard",
        login_at=now,
        last_activity_at=now,
        duration_seconds=0,
        is_active=True,
    )
    db_session.add(session)
    db_session.commit()

    headers = {
        "Authorization": f"Bearer {token}",
        "X-Forwarded-For": "41.89.20.15, 10.0.0.1",
    }

    # Call heartbeat with new current_page
    res = client.post("/auth/heartbeat", json={"current_page": "lan-scanner"}, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["current_page"] == "lan-scanner"

    # Verify database was updated
    db_session.refresh(session)
    assert session.current_page == "lan-scanner"
    assert session.ip_address == "41.89.20.15"
