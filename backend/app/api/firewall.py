from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.firewall_config import FirewallConfig
from ..models.user import User
from ..services.auth_service import require_admin, require_super_admin
from ..services.firewall.manager import (
    get_active_firewall_driver,
    create_driver_instance,
    list_supported_vendors,
    probe_firewall_connection,
)

router = APIRouter(prefix="/firewall", tags=["firewall"])


class FirewallConfigRequest(BaseModel):
    id: int | None = None
    vendor: str = Field(..., description="Firewall vendor id, e.g. 'sophos', 'fortinet', 'mikrotik', 'pfsense'")
    name: str = Field(..., description="Descriptive name for this firewall profile")
    management_url: str = Field("", description="IP or HTTPS management URL")
    api_key: str | None = None
    username: str | None = None
    password: str | None = None
    verify_tls: bool = False
    quarantine_group: str = "NETOPS_Quarantine"
    quarantine_rule: str = "NETOPS_Quarantine_Block"
    is_active: bool = True
    extra_settings: str | None = None


class TestConnectionRequest(BaseModel):
    vendor: str
    management_url: str = ""
    api_key: str | None = None
    username: str | None = None
    password: str | None = None
    verify_tls: bool = False
    quarantine_group: str = "NETOPS_Quarantine"


class QuarantineRequest(BaseModel):
    ip_address: str
    hostname: str | None = None
    mac_address: str | None = None


class UnquarantineRequest(BaseModel):
    ip_address: str
    mac_address: str | None = None


@router.get("/vendors")
def get_supported_vendors():
    """List all supported enterprise and open-source firewall platforms."""
    return list_supported_vendors()


@router.get("/config")
def get_firewall_configuration(db: Session = Depends(get_db)):
    """Return the currently active firewall driver and all saved firewall profiles."""
    active_driver = get_active_firewall_driver(db)
    active_status = active_driver.get_status()

    # Query saved configurations in DB
    saved_configs = db.scalars(select(FirewallConfig).order_by(FirewallConfig.id.asc())).all()

    configs_list = []
    for cfg in saved_configs:
        configs_list.append({
            "id": cfg.id,
            "vendor": cfg.vendor,
            "name": cfg.name,
            "is_active": cfg.is_active,
            "management_url": cfg.management_url,
            "username": cfg.username,
            "has_password": bool(cfg.password),
            "has_api_key": bool(cfg.api_key),
            "verify_tls": cfg.verify_tls,
            "quarantine_group": cfg.quarantine_group,
            "quarantine_rule": cfg.quarantine_rule,
            "created_at": cfg.created_at.isoformat() if cfg.created_at else None,
            "updated_at": cfg.updated_at.isoformat() if cfg.updated_at else None,
        })

    return {
        "active_driver": active_status,
        "saved_configs": configs_list,
    }


@router.post("/config")
def save_firewall_configuration(
    req: FirewallConfigRequest,
    current_user: User = Depends(require_super_admin),
    db: Session = Depends(get_db),
):
    """Create or update a firewall profile and optionally set it as active (Super Admin only)."""
    if req.is_active:
        # Deactivate all other configs
        existing_active = db.scalars(select(FirewallConfig).where(FirewallConfig.is_active == True)).all()
        for c in existing_active:
            c.is_active = False

    target_cfg = None
    if req.id:
        target_cfg = db.scalar(select(FirewallConfig).where(FirewallConfig.id == req.id))

    if target_cfg:
        target_cfg.vendor = req.vendor
        target_cfg.name = req.name
        target_cfg.management_url = req.management_url
        if req.api_key is not None:
            target_cfg.api_key = req.api_key
        if req.username is not None:
            target_cfg.username = req.username
        if req.password is not None and req.password != "••••••••":
            target_cfg.password = req.password
        target_cfg.verify_tls = req.verify_tls
        target_cfg.quarantine_group = req.quarantine_group
        target_cfg.quarantine_rule = req.quarantine_rule
        target_cfg.is_active = req.is_active
        target_cfg.extra_settings = req.extra_settings
    else:
        target_cfg = FirewallConfig(
            vendor=req.vendor,
            name=req.name,
            management_url=req.management_url,
            api_key=req.api_key,
            username=req.username,
            password=req.password if req.password != "••••••••" else None,
            verify_tls=req.verify_tls,
            quarantine_group=req.quarantine_group,
            quarantine_rule=req.quarantine_rule,
            is_active=req.is_active,
            extra_settings=req.extra_settings,
        )
        db.add(target_cfg)

    db.commit()
    db.refresh(target_cfg)

    # Initialize infrastructure if active
    if target_cfg.is_active:
        driver = create_driver_instance(
            vendor=target_cfg.vendor,
            management_url=target_cfg.management_url or "",
            api_key=target_cfg.api_key,
            username=target_cfg.username,
            password=target_cfg.password,
            verify_tls=target_cfg.verify_tls,
            quarantine_group=target_cfg.quarantine_group,
            quarantine_rule=target_cfg.quarantine_rule,
        )
        try:
            driver.ensure_infrastructure()
        except Exception:
            pass

    return {
        "status": "success",
        "message": f"Firewall configuration '{target_cfg.name}' ({target_cfg.vendor}) saved successfully.",
        "config_id": target_cfg.id,
        "is_active": target_cfg.is_active,
    }


@router.post("/activate/{config_id}")
def activate_firewall_configuration(
    config_id: int,
    current_user: User = Depends(require_super_admin),
    db: Session = Depends(get_db),
):
    """Set a specific saved firewall profile as active (Super Admin only)."""
    target = db.scalar(select(FirewallConfig).where(FirewallConfig.id == config_id))
    if not target:
        raise HTTPException(status_code=404, detail="Firewall configuration profile not found.")

    all_configs = db.scalars(select(FirewallConfig)).all()
    for c in all_configs:
        c.is_active = (c.id == config_id)

    db.commit()
    return {"status": "success", "message": f"Firewall profile '{target.name}' is now active."}


@router.post("/test")
def test_firewall_connection(
    req: TestConnectionRequest,
    current_user: User = Depends(require_super_admin),
    db: Session = Depends(get_db),
):
    """Test connection to a firewall appliance using supplied credentials (Super Admin only)."""
    password = req.password
    # If password is placeholder, look up from DB
    if password == "••••••••":
        cfg = db.scalar(select(FirewallConfig).where(FirewallConfig.vendor == req.vendor).order_by(FirewallConfig.id.desc()).limit(1))
        if cfg and cfg.password:
            password = cfg.password

    result = probe_firewall_connection(
        vendor=req.vendor,
        management_url=req.management_url,
        api_key=req.api_key,
        username=req.username,
        password=password,
        verify_tls=req.verify_tls,
        quarantine_group=req.quarantine_group,
    )
    return result


@router.get("/live-status")
def get_live_firewall_status(db: Session = Depends(get_db)):
    """Test reachability and return live status for the active firewall."""
    driver = get_active_firewall_driver(db)
    return driver.test_connection()


@router.post("/quarantine")
def quarantine_device(
    req: QuarantineRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Quarantine an IP on the active firewall (Admins & Super Admins)."""
    driver = get_active_firewall_driver(db)
    return driver.block_device(req.ip_address, req.hostname, req.mac_address)


@router.post("/unquarantine")
def unquarantine_device(
    req: UnquarantineRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Allow an IP on the active firewall (Admins & Super Admins)."""
    driver = get_active_firewall_driver(db)
    return driver.allow_device(req.ip_address, req.mac_address)
