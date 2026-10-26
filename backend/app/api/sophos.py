from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ..config import settings
from ..models.user import User
from ..services.auth_service import require_admin, require_super_admin
from ..services.sophos_enforcement import (
    ensure_sophos_infrastructure,
    is_sophos_configured,
    sophos_allow_device,
    sophos_block_device,
    sophos_test_connection,
)


router = APIRouter(
    prefix="/sophos",
    tags=["Sophos Integration"],
)


class QuarantineRequest(BaseModel):
    ip_address: str
    hostname: str | None = None


class UnquarantineRequest(BaseModel):
    ip_address: str


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
        "enforcement_configured": is_sophos_configured(),
    }


@router.get("/live-status")
def sophos_live_status():
    """Query live Sophos Firewall API for connectivity and active quarantine state."""
    return sophos_test_connection()


@router.post("/test-connection")
def sophos_test_conn(current_user: User = Depends(require_super_admin)):
    """Test connection and ensure quarantine infrastructure is ready on Sophos (Super Admin only)."""
    infra_ready = ensure_sophos_infrastructure()
    result = sophos_test_connection()
    result["infrastructure_ready"] = infra_ready
    return result


@router.post("/quarantine")
def sophos_quarantine_device(
    req: QuarantineRequest,
    current_user: User = Depends(require_admin),
):
    """Manually quarantine an IP address on Sophos Firewall (Admins & Super Admins)."""
    return sophos_block_device(req.ip_address, req.hostname)


@router.post("/unquarantine")
def sophos_unquarantine_device(
    req: UnquarantineRequest,
    current_user: User = Depends(require_admin),
):
    """Manually unquarantine an IP address on Sophos Firewall (Admins & Super Admins)."""
    return sophos_allow_device(req.ip_address)

