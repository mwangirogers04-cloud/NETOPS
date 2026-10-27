"""
Unit and integration tests for NETOPS Real-Time Webhook & Security Alerting System.
"""

from unittest.mock import patch, MagicMock
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models.user import User
from backend.app.models.event import Event
from backend.app.services.auth_service import hash_password
from backend.app.api.auth import clear_failed_login_attempts
from backend.app.services.webhook_service import (
    TRIGGER_QUARANTINE,
    TRIGGER_ROGUE,
    TRIGGER_LOCKOUT,
    TRIGGER_SWITCH_UNREACHABLE,
    TRIGGER_UNAUTHORIZED_CLI,
    build_slack_payload,
    build_discord_payload,
    build_generic_payload,
    map_event_type_to_trigger,
    send_webhook_request,
    verify_webhook_endpoint,
    dispatch_security_alert,
)

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
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
def auth_tokens(test_db):
    test_db.query(User).delete()
    test_db.commit()

    super_admin = User(
        username="netops_dev",
        email="dev@netops.local",
        hashed_password=hash_password("DevPass123!"),
        role="developer",
        is_active=True,
    )
    admin_user = User(
        username="netops_admin",
        email="admin@netops.local",
        hashed_password=hash_password("AdminPass123!"),
        role="admin",
        is_active=True,
    )
    test_db.add_all([super_admin, admin_user])
    test_db.commit()

    clear_failed_login_attempts()

    from backend.app.services.auth_service import create_access_token

    admin_token = create_access_token({"sub": "netops_admin", "role": "admin"})
    super_admin_token = create_access_token({"sub": "netops_dev", "role": "developer"})

    return {
        "admin": admin_token,
        "super_admin": super_admin_token,
    }


def test_map_event_type_to_trigger():
    """Verify that NETOPS event types accurately map to the 5 alert triggers."""
    assert map_event_type_to_trigger("device_quarantined") == TRIGGER_QUARANTINE
    assert map_event_type_to_trigger("device_isolated") == TRIGGER_QUARANTINE
    assert map_event_type_to_trigger("vlan_quarantine") == TRIGGER_QUARANTINE
    assert map_event_type_to_trigger("device_rejected") == TRIGGER_QUARANTINE

    assert map_event_type_to_trigger("new_device") == TRIGGER_ROGUE
    assert map_event_type_to_trigger("device_detected") == TRIGGER_ROGUE
    assert map_event_type_to_trigger("unrecognized_endpoint") == TRIGGER_ROGUE
    assert map_event_type_to_trigger("ip_address_conflict") == TRIGGER_ROGUE

    assert map_event_type_to_trigger("auth_lockout") == TRIGGER_LOCKOUT
    assert map_event_type_to_trigger("account_locked") == TRIGGER_LOCKOUT

    assert map_event_type_to_trigger("switch_unreachable") == TRIGGER_SWITCH_UNREACHABLE
    assert map_event_type_to_trigger("switch_hardware_error") == TRIGGER_SWITCH_UNREACHABLE

    assert map_event_type_to_trigger("unauthorized_cli_change") == TRIGGER_UNAUTHORIZED_CLI
    assert map_event_type_to_trigger("switch_config_drift") == TRIGGER_UNAUTHORIZED_CLI

    assert map_event_type_to_trigger("unrelated_event_xyz") is None


def test_payload_formatters():
    """Verify Slack, Discord, and Generic payload generation schemas."""
    title = "🚨 NETOPS Alert: Device Quarantined"
    msg = "Device 192.168.1.50 was moved to VLAN 90 quarantine."
    details = {"ip": "192.168.1.50", "mac": "AA:BB:CC:DD:EE:FF", "vlan": 90}

    # Slack Payload
    slack = build_slack_payload(title, msg, "device_quarantined", "critical", details)
    assert "attachments" in slack
    assert slack["attachments"][0]["color"] == "#ef4444"
    blocks = slack["attachments"][0]["blocks"]
    assert blocks[0]["text"]["text"] == title
    assert "*Summary:*" in blocks[1]["text"]["text"]

    # Discord Payload
    discord = build_discord_payload(title, msg, "device_quarantined", "critical", details)
    assert "embeds" in discord
    embed = discord["embeds"][0]
    assert embed["title"] == title
    assert embed["color"] == 0xEF4444
    assert any(f["name"] == "Ip" and f["value"] == "192.168.1.50" for f in embed["fields"])

    # Generic Payload
    generic = build_generic_payload(title, msg, "device_quarantined", "critical", details)
    assert generic["platform"] == "netops"
    assert generic["event_type"] == "device_quarantined"
    assert generic["severity"] == "critical"
    assert generic["details"]["mac"] == "AA:BB:CC:DD:EE:FF"


@patch("backend.app.services.webhook_service.httpx.Client")
def test_send_webhook_request_success(mock_client_cls):
    """Test successful webhook HTTP dispatch."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = "ok"

    mock_instance = MagicMock()
    mock_instance.post.return_value = mock_resp
    mock_instance.__enter__.return_value = mock_instance
    mock_client_cls.return_value = mock_instance

    ok, detail = send_webhook_request("https://hooks.slack.com/services/test", {"test": True})
    assert ok is True
    assert "200" in detail


def test_verify_webhook_endpoint_validation():
    """Verify invalid webhook URLs return cleanly without raising unhandled exceptions."""
    ok, detail = verify_webhook_endpoint("not-a-valid-url", "slack")
    assert ok is False
    assert "Invalid webhook URL" in detail


@patch("backend.app.services.webhook_service.httpx.Client")
def test_verify_webhook_endpoint_live(mock_client_cls):
    """Verify live webhook test dispatcher formats and dispatches."""
    mock_resp = MagicMock()
    mock_resp.status_code = 204  # Discord standard success code
    mock_resp.text = ""

    mock_instance = MagicMock()
    mock_instance.post.return_value = mock_resp
    mock_instance.__enter__.return_value = mock_instance
    mock_client_cls.return_value = mock_instance

    ok, detail = verify_webhook_endpoint("https://discord.com/api/webhooks/123/xyz", "discord")
    assert ok is True
    assert "204" in detail


def test_dispatch_security_alert_trigger_filter():
    """Verify that disabled triggers are respected and suppressed."""
    with patch("backend.app.services.webhook_service.get_notification_settings") as mock_cfg:
        mock_cfg.return_value = {
            "webhook_enabled": True,
            "webhook_url": "https://hooks.slack.com/services/test",
            "webhook_platform": "slack",
            "triggers": {
                TRIGGER_QUARANTINE: False,  # Disabled
                TRIGGER_ROGUE: True,
            },
        }

        # Should be suppressed
        res = dispatch_security_alert(
            event_type="device_quarantined",
            message="Test quarantine",
            sync=True,
        )
        assert res["dispatched"] is False
        assert "disabled" in res["reason"]


def test_notifications_api_endpoints(client, auth_tokens):
    """Test API endpoints for reading triggers, settings, saving settings, and testing webhooks."""
    headers = {"Authorization": f"Bearer {auth_tokens['admin']}"}

    # 1. GET /notifications/triggers
    resp = client.get("/notifications/triggers", headers=headers)
    assert resp.status_code == 200
    triggers = resp.json()
    assert len(triggers) == 5
    ids = [t["id"] for t in triggers]
    assert TRIGGER_QUARANTINE in ids
    assert TRIGGER_LOCKOUT in ids
    assert TRIGGER_UNAUTHORIZED_CLI in ids

    # 2. GET /notifications/settings
    resp = client.get("/notifications/settings", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "webhook_platform" in data
    assert "triggers" in data

    # 3. POST /notifications/settings
    update_payload = {
        "webhook_enabled": True,
        "webhook_url": "https://hooks.slack.com/services/T00/B00/X00",
        "webhook_platform": "slack",
        "alert_email": "noc-team@netops.local",
        "alert_email_enabled": True,
        "triggers": {
            TRIGGER_QUARANTINE: True,
            TRIGGER_ROGUE: True,
            TRIGGER_LOCKOUT: True,
            TRIGGER_SWITCH_UNREACHABLE: True,
            TRIGGER_UNAUTHORIZED_CLI: True,
        },
    }
    resp = client.post("/notifications/settings", json=update_payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "saved"

    # Verify settings persisted
    resp = client.get("/notifications/settings", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["webhook_enabled"] is True
    assert resp.json()["alert_email"] == "noc-team@netops.local"

    # 4. POST /notifications/test (mocked)
    with patch("backend.app.api.notifications.test_webhook_endpoint") as mock_test:
        mock_test.return_value = (True, "HTTP 200 OK")
        test_payload = {
            "channel": "webhook",
            "recipient": "https://hooks.slack.com/services/T00/B00/X00",
            "webhook_platform": "slack",
        }
        resp = client.post("/notifications/test", json=test_payload, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["delivered"] is True


def test_auth_lockout_triggers_security_event_and_alert(client, test_db):
    """Verify that 3 consecutive failed logins create an auth_lockout event."""
    clear_failed_login_attempts()

    user = User(
        username="sec_target",
        email="target@netops.local",
        hashed_password=hash_password("TargetP@ss1"),
        role="operator",
        is_active=True,
    )
    test_db.add(user)
    test_db.commit()

    # Attempt 1: Failed
    r1 = client.post("/auth/login", json={"username": "sec_target", "password": "WrongPassword1"})
    assert r1.status_code == 401
    assert "2 attempts remaining" in r1.json()["detail"]

    # Attempt 2: Failed
    r2 = client.post("/auth/login", json={"username": "sec_target", "password": "WrongPassword2"})
    assert r2.status_code == 401
    assert "1 attempt remaining" in r2.json()["detail"]

    # Attempt 3: Lockout!
    with patch("backend.app.api.auth.dispatch_security_alert") as mock_alert:
        r3 = client.post("/auth/login", json={"username": "sec_target", "password": "WrongPassword3"})
        assert r3.status_code == 401
        assert "entered an incorrect password 3 times" in r3.json()["detail"]
        assert mock_alert.called
        assert mock_alert.call_args[1]["event_type"] == "auth_lockout"

    # Verify audit event logged in DB
    ev = test_db.query(Event).filter(Event.event_type == "auth_lockout").first()
    assert ev is not None
    assert "sec_target" in ev.message
