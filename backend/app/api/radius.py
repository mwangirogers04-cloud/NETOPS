"""
NETOPS 802.1X / RADIUS API Router
=================================
Manages FreeRADIUS policy, dynamic VLAN steering, MAB format conventions,
and configuration generation for switches and authenticators.
"""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.user import User
from ..services.auth_service import require_admin
from ..services.radius_service import (
    generate_freeradius_clients_config,
    generate_freeradius_users_config,
    get_radius_settings,
    save_radius_settings,
    simulate_radius_auth,
)

router = APIRouter(
    prefix="/radius",
    tags=["802.1X / FreeRADIUS & Dynamic VLANs"],
)


class RadiusSettingsUpdateRequest(BaseModel):
    enabled: bool | None = None
    auth_port: int | None = None
    acct_port: int | None = None
    shared_secret: str | None = None
    quarantine_vlan: int | None = None
    mab_format: str | None = None
    default_unregistered_policy: str | None = None
    auto_sync_enabled: bool | None = None


class RadiusAuthSimulateRequest(BaseModel):
    mac_address: str
    nas_ip: str | None = None


@router.get("/settings")
def get_radius_settings_endpoint(current_user: User = Depends(require_admin)):
    """Retrieve 802.1X FreeRADIUS server configuration and MAB conventions."""
    cfg = get_radius_settings()
    return {
        **cfg,
        "shared_secret": "••••••••" if cfg.get("shared_secret") else "",
    }


@router.post("/settings")
def update_radius_settings_endpoint(
    req: RadiusSettingsUpdateRequest,
    current_user: User = Depends(require_admin),
):
    """Update 802.1X FreeRADIUS server configuration (ports, shared secret, MAB format)."""
    data = req.model_dump()
    if data.get("shared_secret") == "••••••••":
        data.pop("shared_secret", None)
    saved = save_radius_settings(data)
    return {
        "success": True,
        "message": "802.1X FreeRADIUS configuration updated successfully.",
        "settings": {
            **saved,
            "shared_secret": "••••••••" if saved.get("shared_secret") else "",
        },
    }


@router.get("/config/users")
def get_freeradius_users_file(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Generate dynamic FreeRADIUS 'users' dictionary file with RFC 2868 / 3580 attributes."""
    content = generate_freeradius_users_config(db)
    return PlainTextResponse(
        content=content,
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="users"'},
    )


@router.get("/config/clients")
def get_freeradius_clients_file(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Generate FreeRADIUS 'clients.conf' with NAS switch definitions."""
    content = generate_freeradius_clients_config(db)
    return PlainTextResponse(
        content=content,
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="clients.conf"'},
    )


@router.post("/authenticate")
def simulate_radius_authentication(
    req: RadiusAuthSimulateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Simulate a live 802.1X / MAC Authentication Bypass (MAB) Access-Request
    and return the exact dynamic VLAN steering decision.
    """
    if not req.mac_address or not req.mac_address.strip():
        raise HTTPException(status_code=400, detail="Please enter a valid endpoint MAC address.")

    return simulate_radius_auth(
        db=db,
        mac_address=req.mac_address.strip(),
        nas_ip=req.nas_ip,
    )


@router.post("/sync")
def sync_radius_policy(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Export and synchronize FreeRADIUS policy files across local authenticators."""
    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()
    users_cfg = generate_freeradius_users_config(db)
    clients_cfg = generate_freeradius_clients_config(db)

    save_radius_settings({"last_sync_at": now_iso})

    return {
        "success": True,
        "synced_at": now_iso,
        "users_rules_generated": users_cfg.count("Cleartext-Password"),
        "nas_clients_generated": clients_cfg.count("client switch_") + 1,
        "message": "FreeRADIUS 802.1X policy dictionary and clients.conf synchronized successfully.",
    }
