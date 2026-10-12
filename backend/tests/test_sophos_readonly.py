from unittest.mock import Mock, patch

import pytest

from backend.app.services.sophos_readonly import (
    _get_configuration,
    get_readonly,
)


def test_configuration_rejects_http_url():
    with (
        patch(
            "backend.app.services.sophos_readonly.settings.sophos_base_url",
            "http://firewall.example.invalid",
        ),
        patch(
            "backend.app.services.sophos_readonly.settings.sophos_api_token",
            "test-token",
        ),
    ):
        with pytest.raises(RuntimeError, match="HTTPS"):
            _get_configuration()


def test_configuration_rejects_missing_token():
    with (
        patch(
            "backend.app.services.sophos_readonly.settings.sophos_base_url",
            "https://firewall.example.invalid",
        ),
        patch(
            "backend.app.services.sophos_readonly.settings.sophos_api_token",
            "",
        ),
    ):
        with pytest.raises(RuntimeError, match="token"):
            _get_configuration()


@pytest.mark.parametrize(
    "path",
    [
        "https://example.invalid/api",
        "//example.invalid/api",
        "/../admin",
        "/api/../admin",
        "/api/firewall-config/v1/test?admin=true",
        "/api/firewall-config/v1/test#fragment",
    ],
)
def test_readonly_rejects_unsafe_path(path):
    with pytest.raises(ValueError):
        get_readonly(path)


def test_readonly_rejects_unsafe_path_before_http_request():
    with patch(
        "backend.app.services.sophos_readonly.httpx.Client"
    ) as mock_client_class:
        with pytest.raises(ValueError):
            get_readonly("https://example.invalid/api")

    mock_client_class.assert_not_called()


def test_readonly_get_returns_json():
    mock_response = Mock()
    mock_response.is_error = False
    mock_response.json.return_value = {"status": "ok"}

    with (
        patch(
            "backend.app.services.sophos_readonly.settings.sophos_base_url",
            "https://firewall.example.invalid",
        ),
        patch(
            "backend.app.services.sophos_readonly.settings.sophos_api_token",
            "test-token",
        ),
        patch(
            "backend.app.services.sophos_readonly.httpx.Client"
        ) as mock_client_class,
    ):
        mock_client = mock_client_class.return_value.__enter__.return_value
        mock_client.get.return_value = mock_response

        result = get_readonly("/api/firewall-config/v1/test")

    assert result == {"status": "ok"}
    mock_client.get.assert_called_once_with(
        "https://firewall.example.invalid/api/firewall-config/v1/test",
        headers={
            "Authorization": "Bearer test-token",
            "Accept": "application/json",
        },
    )


def test_readonly_hides_http_error_details():
    mock_response = Mock()
    mock_response.is_error = True
    mock_response.status_code = 403
    mock_response.text = "Sensitive server response"

    with (
        patch(
            "backend.app.services.sophos_readonly.settings.sophos_base_url",
            "https://firewall.example.invalid",
        ),
        patch(
            "backend.app.services.sophos_readonly.settings.sophos_api_token",
            "test-token",
        ),
        patch(
            "backend.app.services.sophos_readonly.httpx.Client"
        ) as mock_client_class,
    ):
        mock_client = mock_client_class.return_value.__enter__.return_value
        mock_client.get.return_value = mock_response

        with pytest.raises(RuntimeError, match="HTTP 403") as exc:
            get_readonly("/api/firewall-config/v1/test")

    assert "Sensitive server response" not in str(exc.value)
    assert "test-token" not in str(exc.value)
