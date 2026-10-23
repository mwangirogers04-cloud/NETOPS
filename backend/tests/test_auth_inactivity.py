from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, select
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


def test_auth_me_enforces_three_minute_inactivity_logout(client, db_session):
    """
    After 3 minutes of inactivity (last_activity_at > 180 seconds ago),
    the system automatically expires the user session and returns 401.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    user = User(
        username="inactive_user",
        email="inactive@example.com",
        hashed_password=hash_password("Password123!"),
        role="user",
        is_verified=True,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    # Active session that has been inactive for 4 minutes (> 180s)
    session = UserSession(
        user_id=user.id,
        username=user.username,
        role=user.role,
        login_at=now - timedelta(minutes=5),
        last_activity_at=now - timedelta(minutes=4),
        duration_seconds=60,
        is_active=True,
    )
    db_session.add(session)
    db_session.commit()
    db_session.refresh(session)

    token = create_access_token({"sub": user.username, "session_id": session.id})

    # Calling /auth/me should reject due to 3-minute inactivity
    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert "3 minutes of inactivity" in response.json()["detail"]

    # Session in DB should now be marked inactive
    db_session.refresh(session)
    assert session.is_active is False
    assert session.logout_at is not None


def test_auth_heartbeat_enforces_three_minute_inactivity_logout(client, db_session):
    """
    Heartbeat called after 3 minutes of inactivity expires the session with 401.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    user = User(
        username="idle_user",
        email="idle@example.com",
        hashed_password=hash_password("Password123!"),
        role="user",
        is_verified=True,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    session = UserSession(
        user_id=user.id,
        username=user.username,
        role=user.role,
        login_at=now - timedelta(minutes=10),
        last_activity_at=now - timedelta(minutes=3, seconds=10),
        duration_seconds=300,
        is_active=True,
    )
    db_session.add(session)
    db_session.commit()
    db_session.refresh(session)

    token = create_access_token({"sub": user.username, "session_id": session.id})

    response = client.post(
        "/auth/heartbeat",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert "3 minutes of inactivity" in response.json()["detail"]

    db_session.refresh(session)
    assert session.is_active is False


def test_auth_me_allows_active_session_within_three_minutes(client, db_session):
    """
    Session with activity within the last 3 minutes remains valid and updates last_activity_at.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    user = User(
        username="active_user",
        email="active@example.com",
        hashed_password=hash_password("Password123!"),
        role="user",
        is_verified=True,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    # Activity was 30 seconds ago (< 180s)
    session = UserSession(
        user_id=user.id,
        username=user.username,
        role=user.role,
        login_at=now - timedelta(minutes=1),
        last_activity_at=now - timedelta(seconds=30),
        duration_seconds=30,
        is_active=True,
    )
    db_session.add(session)
    db_session.commit()
    db_session.refresh(session)

    token = create_access_token({"sub": user.username, "session_id": session.id})

    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["username"] == "active_user"

    db_session.refresh(session)
    assert session.is_active is True
