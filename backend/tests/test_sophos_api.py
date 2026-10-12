from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.api.sophos import settings
from backend.app.main import app


client = TestClient(app)


def test_sophos_status_reports_unconfigured():
    with (
        patch.object(settings, "sophos_base_url", ""),
        patch.object(settings, "sophos_api_token", ""),
        patch.object(settings, "sophos_verify_tls", True),
    ):
        response = client.get("/sophos/status")

    assert response.status_code == 200

    data = response.json()
    assert data["configured"] is False
    assert data["management_url_configured"] is False
    assert data["credentials_configured"] is False
    assert data["connection_tested"] is False
    assert data["mode"] == "read-only"
    assert data["tls_verification"] is True


def test_sophos_status_reports_configuration_without_claiming_connection():
    with (
        patch.object(
            settings,
            "sophos_base_url",
            "https://firewall.example.invalid",
        ),
        patch.object(settings, "sophos_api_token", "test-token"),
        patch.object(settings, "sophos_verify_tls", True),
    ):
        response = client.get("/sophos/status")

    assert response.status_code == 200

    data = response.json()
    assert data["configured"] is True
    assert data["management_url_configured"] is True
    assert data["credentials_configured"] is True
    assert data["connection_tested"] is False
    assert data["mode"] == "read-only"
    assert "test-token" not in response.text
