import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models.device import Device
from backend.app.models.user import User
from backend.app.models.web_activity import WebActivityLog, WebFilterPolicy
from backend.app.services.auth_service import create_access_token, hash_password
from backend.app.services.web_categorizer import categorize_domain, is_prohibited_during_work
from backend.app.services.web_traffic_sniffer import (
    record_web_activity,
    get_web_activity_analytics,
    get_or_create_web_policy,
)

TEST_DB_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def setup_db():
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
    test_client = TestClient(app)

    admin = db_session.query(User).filter(User.username == "admin_test").first()
    if not admin:
        admin = User(
            username="admin_test",
            email="admin_test@example.com",
            hashed_password=hash_password("Admin@1234"),
            role="super_admin",
            is_active=True,
            is_verified=True,
        )
        db_session.add(admin)
        db_session.commit()
    token = create_access_token({"sub": admin.username, "role": admin.role, "user_id": admin.id})
    test_client.headers.update({"Authorization": f"Bearer {token}"})

    yield test_client
    app.dependency_overrides.clear()


def test_web_categorization_engine():
    # Streaming
    assert categorize_domain("youtube.com") == "streaming"
    assert categorize_domain("rr3---sn-4g5edn6s.googlevideo.com") == "streaming"
    assert categorize_domain("www.netflix.com") == "streaming"
    assert categorize_domain("twitch.tv") == "streaming"
    assert categorize_domain("disneyplus.com") == "streaming"

    # Gaming
    assert categorize_domain("steampowered.com") == "gaming"
    assert categorize_domain("store.epicgames.com") == "gaming"
    assert categorize_domain("roblox.com") == "gaming"
    assert categorize_domain("discord.gg") == "gaming"

    # Social Media
    assert categorize_domain("m.facebook.com") == "social_media"
    assert categorize_domain("instagram.com") == "social_media"
    assert categorize_domain("tiktok.com") == "social_media"
    assert categorize_domain("x.com") == "social_media"

    # Gambling / Adult
    assert categorize_domain("betway.co.ke") == "gambling_adult"
    assert categorize_domain("sportpesa.com") == "gambling_adult"

    # Productivity
    assert categorize_domain("github.com") == "productivity"
    assert categorize_domain("office.com") == "productivity"
    assert categorize_domain("docs.google.com") == "productivity"


def test_record_web_activity_and_correlation(db_session):
    # Setup test device
    dev = Device(
        mac_address="A4:4E:31:AD:0E:28",
        ip_address="192.168.0.104",
        hostname="DESKTOP-8N0NNSL",
        device_type="computer",
        status="online",
        approval_status="approved",
    )
    db_session.add(dev)
    db_session.commit()

    # Record streaming activity
    entry = record_web_activity(
        db=db_session,
        ip_address="192.168.0.104",
        domain="www.youtube.com",
        protocol="DNS",
    )
    assert entry is not None
    assert entry.domain == "www.youtube.com"
    assert entry.category == "streaming"
    assert entry.hostname == "DESKTOP-8N0NNSL"
    assert entry.device_id == dev.id

    # Record gaming activity
    entry_gaming = record_web_activity(
        db=db_session,
        ip_address="192.168.0.104",
        domain="store.steampowered.com",
        protocol="DNS",
    )
    assert entry_gaming is not None
    assert entry_gaming.category == "gaming"

    # Analytics
    analytics = get_web_activity_analytics(db=db_session, hours=24)
    assert analytics["total_queries"] >= 2
    assert "streaming" in analytics["category_counts"]
    assert "gaming" in analytics["category_counts"]
    assert len(analytics["top_streaming_devices"]) >= 1


def test_web_activity_api_endpoints(client, db_session):
    # 1. Post manual log
    post_res = client.post("/web-activity/log", json={
        "ip_address": "192.168.0.103",
        "domain": "netflix.com",
        "protocol": "PROBE",
    })
    assert post_res.status_code == 200
    data = post_res.json()
    assert data["domain"] == "netflix.com"
    assert data["category"] == "streaming"

    # 2. Get logs
    get_res = client.get("/web-activity/logs")
    assert get_res.status_code == 200
    logs = get_res.json()
    assert len(logs) >= 1
    assert any(l["domain"] == "netflix.com" for l in logs)

    # 3. Get analytics
    stats_res = client.get("/web-activity/analytics?hours=24")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["total_queries"] >= 1

    # 4. Get & Update policy
    policy_res = client.get("/web-activity/policy")
    assert policy_res.status_code == 200
    policy = policy_res.json()
    assert "block_streaming_work_hours" in policy

    put_res = client.put("/web-activity/policy", json={
        "block_streaming_work_hours": True,
        "block_gaming_work_hours": True,
        "block_social_media_work_hours": True,
    })
    assert put_res.status_code == 200
    updated = put_res.json()
    assert updated["block_social_media_work_hours"] is True

def test_active_sessions_and_time_filters(client, db_session):
    # Post an entry
    client.post("/web-activity/log", json={
        "ip_address": "192.168.0.107",
        "domain": "zeno.fm",
        "protocol": "DNS",
    })

    # Test active sessions endpoint
    res = client.get("/web-activity/active-sessions?minutes=5")
    assert res.status_code == 200
    sessions = res.json()
    assert len(sessions) >= 1
    assert any(s["domain"] == "zeno.fm" and s["ip_address"] == "192.168.0.107" for s in sessions)

    # Test minutes filter on logs
    logs_res = client.get("/web-activity/logs?minutes=5")
    assert logs_res.status_code == 200
    assert len(logs_res.json()) >= 1

    # Test clear logs
    del_res = client.delete("/web-activity/logs")
    assert del_res.status_code == 200

    # Test agent-sync endpoint
    agent_sync_res = client.post("/web-activity/agent-sync", json={
        "ip_address": "192.168.0.104",
        "hostname": "DESKTOP-8N0NNSL",
        "domains": ["github.com", "twitch.tv", "reddit.com"],
        "protocol": "AGENT_CACHE",
    })
    assert agent_sync_res.status_code == 200
    sync_data = agent_sync_res.json()
    assert sync_data["status"] == "success"
    assert sync_data["domains_received"] == 3
    assert sync_data["recorded_new_entries"] >= 1

    # Test trigger-scan endpoint
    scan_res = client.post("/web-activity/trigger-scan")
    assert scan_res.status_code == 200
    scan_data = scan_res.json()
    assert scan_data["status"] == "completed"
    assert "active_sessions_count" in scan_data

    # Ensure logs contains agent-synced items
    logs_res_after = client.get("/web-activity/logs")
    assert logs_res_after.status_code == 200
    assert len(logs_res_after.json()) >= 1
