from urllib.parse import urlparse

import httpx

from ..config import settings


def _get_configuration() -> tuple[str, str]:
    """Validate Sophos API configuration without making a request."""
    base_url = settings.sophos_base_url.strip().rstrip("/")
    token = settings.sophos_api_token.strip()

    parsed = urlparse(base_url)

    if parsed.scheme != "https" or not parsed.hostname:
        raise RuntimeError(
            "Sophos management URL must be a valid HTTPS URL."
        )

    if parsed.username or parsed.password:
        raise RuntimeError(
            "Credentials must not be embedded in the Sophos URL."
        )

    if not token:
        raise RuntimeError(
            "Sophos API token is not configured."
        )

    return base_url, token


def check_sophos_configuration() -> dict[str, bool | str]:
    """Report configuration readiness without contacting the firewall."""
    base_url, _ = _get_configuration()

    return {
        "configured": True,
        "management_url_configured": True,
        "credentials_configured": True,
        "connection_tested": False,
        "mode": "read-only",
        "tls_verification": settings.sophos_verify_tls,
        "scheme": urlparse(base_url).scheme,
    }


def get_readonly(
    api_path: str,
    *,
    timeout: float = 10.0,
) -> dict | list:
    """
    Send a read-only GET request to a verified Sophos API endpoint.

    Only relative API paths are accepted. The exact path must be
    confirmed against the installed firewall's supported API.
    """
    if (
        not api_path.startswith("/api/firewall-config/v1/")
        or api_path.startswith("//")
        or "://" in api_path
        or ".." in api_path.split("/")
        or "?" in api_path
        or "#" in api_path
    ):
        raise ValueError(
            "A valid relative Sophos REST API path is required."
        )
    base_url, token = _get_configuration()

    with httpx.Client(
        verify=settings.sophos_verify_tls,
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        response = client.get(
            f"{base_url}{api_path}",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
        )

    if response.is_error:
        raise RuntimeError(
            f"Sophos API returned HTTP {response.status_code}."
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError(
            "Sophos API returned an invalid JSON response."
        ) from exc

    if not isinstance(payload, (dict, list)):
        raise RuntimeError(
            "Sophos API returned an unexpected response format."
        )

    return payload
