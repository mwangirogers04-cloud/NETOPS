from fastapi import APIRouter

from ..config import settings


router = APIRouter(
    prefix="/sophos",
    tags=["Sophos Read-Only"],
)


@router.get("/status")
def sophos_status():
    """Report configuration readiness without connecting to Sophos."""

    url_configured = bool(settings.sophos_base_url.strip())
    token_configured = bool(settings.sophos_api_token.strip())

    return {
        "service": "Sophos read-only integration",
        "configured": url_configured and token_configured,
        "management_url_configured": url_configured,
        "credentials_configured": token_configured,
        "connection_tested": False,
        "mode": "read-only",
        "tls_verification": settings.sophos_verify_tls,
    }
