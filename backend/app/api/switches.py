import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.switch_config import SwitchConfig
from ..models.vlan_config import VlanConfig
from ..models.user import User
from ..services.auth_service import require_admin, require_super_admin
from ..services.event_service import create_event
from ..services.switch.manager import (
    create_switch_driver,
    get_active_switch_driver,
    list_supported_switch_vendors,
    probe_switch_connection,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/switches", tags=["switches"])


# -------------------------------------------------------------
# SCHEMAS
# -------------------------------------------------------------

class SwitchConfigRequest(BaseModel):
    id: int | None = None
    vendor: str = Field(..., description="Switch vendor id, e.g. 'cisco_ios', 'aruba', 'mikrotik', 'simulation'")
    name: str = Field(..., description="Descriptive name for this switch, e.g. 'Core Switch Cisco 2960'")
    management_ip: str = Field(..., description="IPv4 address of the switch management interface")
    port: int = Field(22, description="SSH or management port")
    username: str | None = None
    password: str | None = None
    enable_secret: str | None = None
    connection_protocol: str = "ssh"
    model: str | None = None
    total_ports: int = 24
    description: str | None = None
    is_active: bool = True


class TestSwitchConnectionRequest(BaseModel):
    vendor: str
    management_ip: str
    port: int = 22
    username: str | None = None
    password: str | None = None
    enable_secret: str | None = None


class CreateVlanRequest(BaseModel):
    vlan_id: int = Field(..., ge=1, le=4094, description="VLAN ID between 1 and 4094")
    name: str = Field(..., description="VLAN name, e.g. 'Finance_Dept'")
    description: str | None = None
    subnet: str | None = None


class UpdateVlanRequest(BaseModel):
    name: str = Field(..., description="VLAN name, e.g. 'HR_Management' or 'IT_Operations'")
    description: str | None = None
    subnet: str | None = None


class AssignPortVlanRequest(BaseModel):
    port_name: str = Field(..., description="Switch physical port, e.g. 'GigabitEthernet0/1'")
    vlan_id: int = Field(1, ge=1, le=4094, description="Target VLAN ID (or Native VLAN for Trunk)")
    mode: str = Field("access", description="'access' or 'trunk'")
    is_trunk: bool = Field(False, description="Tick to configure as 802.1Q trunk uplink port")


class ConfigureUplinksRequest(BaseModel):
    ports: list[str] | None = None
    native_vlan: int = Field(1, ge=1, le=4094)
    mode: str = Field("trunk")


# -------------------------------------------------------------
# VENDORS & CONFIGURATION ENDPOINTS
# -------------------------------------------------------------

@router.get("/vendors")
def get_supported_vendors():
    """List all supported switch vendors with connection metadata."""
    return list_supported_switch_vendors()


@router.get("/configs")
def list_switch_configs(db: Session = Depends(get_db)):
    """List all saved switch profiles."""
    configs = db.scalars(select(SwitchConfig).order_by(SwitchConfig.created_at.desc())).all()
    results = []
    for c in configs:
        results.append({
            "id": c.id,
            "vendor": c.vendor,
            "name": c.name,
            "management_ip": c.management_ip,
            "port": c.port,
            "username": c.username,
            "has_password": bool(c.password),
            "has_enable_secret": bool(c.enable_secret),
            "connection_protocol": c.connection_protocol,
            "model": c.model,
            "total_ports": c.total_ports,
            "description": c.description,
            "is_active": c.is_active,
            "last_status": c.last_status,
            "last_tested_at": c.last_tested_at.isoformat() if c.last_tested_at else None,
            "created_at": c.created_at.isoformat() if c.created_at else None,
        })
    return results


@router.post("/configs")
def create_or_update_switch_config(
    req: SwitchConfigRequest,
    current_user: User = Depends(require_super_admin),
    db: Session = Depends(get_db),
):
    """Create or update a switch profile (Super Admin / Developers only)."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    if req.is_active:
        # Deactivate other active switches if setting this one active
        db.query(SwitchConfig).filter(SwitchConfig.is_active == True).update({"is_active": False})

    if req.id:
        cfg = db.get(SwitchConfig, req.id)
        if not cfg:
            raise HTTPException(status_code=404, detail="Switch profile not found.")
        cfg.vendor = req.vendor
        cfg.name = req.name
        cfg.management_ip = req.management_ip.strip()
        cfg.port = req.port
        cfg.username = req.username.strip() if req.username else None
        if req.password:
            cfg.password = req.password
        if req.enable_secret:
            cfg.enable_secret = req.enable_secret
        cfg.connection_protocol = req.connection_protocol
        cfg.model = req.model
        cfg.total_ports = req.total_ports
        cfg.description = req.description
        cfg.is_active = req.is_active
        cfg.updated_at = now
    else:
        cfg = SwitchConfig(
            vendor=req.vendor,
            name=req.name,
            management_ip=req.management_ip.strip(),
            port=req.port,
            username=req.username.strip() if req.username else None,
            password=req.password,
            enable_secret=req.enable_secret,
            connection_protocol=req.connection_protocol,
            model=req.model,
            total_ports=req.total_ports,
            description=req.description,
            is_active=req.is_active,
            last_status="configured",
            created_at=now,
            updated_at=now,
        )
        db.add(cfg)

    db.commit()
    db.refresh(cfg)

    create_event(
        db=db,
        event_type="switch_configured",
        message=f"Switch profile '{cfg.name}' ({cfg.vendor} at {cfg.management_ip}) saved by {current_user.username}.",
        device_id=None,
        actor=current_user.username,
    )
    db.commit()

    return {
        "id": cfg.id,
        "name": cfg.name,
        "vendor": cfg.vendor,
        "management_ip": cfg.management_ip,
        "is_active": cfg.is_active,
        "message": f"Switch profile '{cfg.name}' saved successfully.",
    }


@router.post("/configs/{config_id}/activate")
def activate_switch_config(
    config_id: int,
    current_user: User = Depends(require_super_admin),
    db: Session = Depends(get_db),
):
    """Set a specific switch configuration profile as active (Super Admin only)."""
    cfg = db.get(SwitchConfig, config_id)
    if not cfg:
        raise HTTPException(status_code=404, detail="Switch profile not found.")

    db.query(SwitchConfig).filter(SwitchConfig.id != config_id).update({"is_active": False})
    cfg.is_active = True
    cfg.updated_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()

    create_event(
        db=db,
        event_type="switch_activated",
        message=f"Switch '{cfg.name}' ({cfg.management_ip}) activated by {current_user.username}.",
        device_id=None,
        actor=current_user.username,
    )
    db.commit()

    return {"message": f"Switch '{cfg.name}' is now active.", "id": cfg.id}


@router.delete("/configs/{config_id}")
def delete_switch_config(
    config_id: int,
    current_user: User = Depends(require_super_admin),
    db: Session = Depends(get_db),
):
    """Delete a switch profile (Super Admin only)."""
    cfg = db.get(SwitchConfig, config_id)
    if not cfg:
        raise HTTPException(status_code=404, detail="Switch profile not found.")

    name = cfg.name
    db.delete(cfg)
    db.commit()

    create_event(
        db=db,
        event_type="switch_deleted",
        message=f"Switch profile '{name}' deleted by {current_user.username}.",
        device_id=None,
        actor=current_user.username,
    )
    db.commit()

    return {"message": f"Switch profile '{name}' deleted."}


@router.post("/test-connection")
def test_switch_connection(
    req: TestSwitchConnectionRequest,
    current_user: User = Depends(require_super_admin),
):
    """Test reachability and credentials against a switch (Super Admin only)."""
    return probe_switch_connection(
        vendor=req.vendor,
        management_ip=req.management_ip.strip(),
        port=req.port,
        username=req.username.strip() if req.username else None,
        password=req.password,
        enable_secret=req.enable_secret,
    )


@router.get("/active")
def get_active_switch(db: Session = Depends(get_db)):
    """Retrieve active switch status and live metadata."""
    active_cfg = db.scalar(select(SwitchConfig).where(SwitchConfig.is_active == True).limit(1))
    driver = get_active_switch_driver(db)

    test_res = driver.test_connection()
    return {
        "has_active_switch": active_cfg is not None,
        "config": {
            "id": active_cfg.id if active_cfg else None,
            "name": active_cfg.name if active_cfg else "Default Switch Environment / Simulator",
            "vendor": active_cfg.vendor if active_cfg else driver.get_vendor_id(),
            "management_ip": active_cfg.management_ip if active_cfg else "127.0.0.1",
            "port": active_cfg.port if active_cfg else 22,
            "model": active_cfg.model if active_cfg else "Catalyst 2960-X",
            "total_ports": active_cfg.total_ports if active_cfg else 24,
        },
        "driver_title": driver.get_vendor_title(),
        "connection": test_res,
    }


# -------------------------------------------------------------
# LIVE VLAN MANAGEMENT ENDPOINTS (CRUD)
# -------------------------------------------------------------

@router.get("/vlans")
def list_switch_vlans(db: Session = Depends(get_db)):
    """
    List all VLANs currently active on the switch (merged with registered database VLANs).
    """
    driver = get_active_switch_driver(db)
    switch_vlans = driver.get_vlans()

    # Get local metadata from DB
    db_vlans = db.scalars(select(VlanConfig)).all()
    db_map = {v.vlan_id: v for v in db_vlans}

    results = []
    seen = set()

    for sv in switch_vlans:
        vid = sv["vlan_id"]
        seen.add(vid)
        meta = db_map.get(vid)
        results.append({
            "vlan_id": vid,
            "name": sv.get("name") or (meta.name if meta else f"VLAN_{vid}"),
            "status": sv.get("status", "active"),
            "ports": sv.get("ports", ""),
            "description": meta.description if meta else None,
            "subnet": meta.subnet if meta else None,
            "is_quarantine": vid == 90 or (meta.is_quarantine if meta else False),
            "is_default": vid in (1, 1002, 1003, 1004, 1005),
        })

    # Add any DB records not in switch output
    for v in db_vlans:
        if v.vlan_id not in seen:
            results.append({
                "vlan_id": v.vlan_id,
                "name": v.name,
                "status": "staged",
                "ports": "",
                "description": v.description,
                "subnet": v.subnet,
                "is_quarantine": v.is_quarantine or v.vlan_id == 90,
                "is_default": v.vlan_id in (1, 1002, 1003, 1004, 1005),
            })

    results.sort(key=lambda x: x["vlan_id"])
    return results


@router.post("/vlans")
def create_switch_vlan(
    req: CreateVlanRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Create a new VLAN directly on the switch and save it to the NETOPS database.
    (Eliminates the need to open console / CLI manually).
    """
    clean_name = req.name.strip().replace(" ", "_")
    driver = get_active_switch_driver(db)

    # 1. Push to switch
    result = driver.create_vlan(req.vlan_id, clean_name)

    # 2. Persist in database
    existing = db.scalar(select(VlanConfig).where(VlanConfig.vlan_id == req.vlan_id))
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    if existing:
        existing.name = clean_name
        existing.description = req.description
        existing.subnet = req.subnet
        existing.is_quarantine = req.vlan_id == 90
        existing.updated_at = now
    else:
        vlan_rec = VlanConfig(
            vlan_id=req.vlan_id,
            name=clean_name,
            description=req.description,
            subnet=req.subnet,
            is_quarantine=req.vlan_id == 90,
            created_by=current_user.username,
            created_at=now,
            updated_at=now,
        )
        db.add(vlan_rec)

    db.commit()

    # 3. Audit log
    create_event(
        db=db,
        event_type="vlan_created",
        message=(
            f"VLAN {req.vlan_id} ('{clean_name}') created on switch by "
            f"{current_user.role} '{current_user.username}'."
        ),
        device_id=None,
        actor=current_user.username,
    )
    db.commit()

    return {
        "success": True,
        "vlan_id": req.vlan_id,
        "name": clean_name,
        "message": f"VLAN {req.vlan_id} ('{clean_name}') successfully provisioned on switch.",
        "commands_applied": result.get("commands_applied", []),
    }


@router.put("/vlans/{vlan_id}")
def update_switch_vlan(
    vlan_id: int,
    req: UpdateVlanRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Update an existing VLAN name, description, and subnet on both switch and database.
    Allows companies to configure custom department VLANs (e.g. HR Management, IT Operations, Finance).
    """
    clean_name = req.name.strip().replace(" ", "_")
    driver = get_active_switch_driver(db)

    # 1. Update on live switch
    result = driver.create_vlan(vlan_id, clean_name)

    # 2. Persist in database
    existing = db.scalar(select(VlanConfig).where(VlanConfig.vlan_id == vlan_id))
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    if existing:
        existing.name = clean_name
        existing.description = req.description
        existing.subnet = req.subnet
        existing.updated_at = now
    else:
        existing = VlanConfig(
            vlan_id=vlan_id,
            name=clean_name,
            description=req.description,
            subnet=req.subnet,
            is_quarantine=vlan_id == 90,
            created_by=current_user.username,
            created_at=now,
            updated_at=now,
        )
        db.add(existing)

    db.commit()

    # 3. Audit log
    create_event(
        db=db,
        event_type="vlan_updated",
        message=(
            f"VLAN {vlan_id} updated to '{clean_name}' ({req.description or 'Custom department'}) "
            f"by {current_user.role} '{current_user.username}'."
        ),
        device_id=None,
        actor=current_user.username,
    )
    db.commit()

    return {
        "success": True,
        "vlan_id": vlan_id,
        "name": clean_name,
        "description": req.description,
        "subnet": req.subnet,
        "message": f"VLAN {vlan_id} successfully updated to '{clean_name}' on switch and database.",
        "commands_applied": result.get("commands_applied", []),
    }


@router.delete("/vlans/{vlan_id}")
def delete_switch_vlan(
    vlan_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Delete a VLAN from the switch and from NETOPS database.
    Reserved VLANs (1, 1002-1005) and Quarantine VLAN 90 are protected.
    """
    if vlan_id in (1, 1002, 1003, 1004, 1005):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"VLAN {vlan_id} is a reserved system default VLAN and cannot be deleted.",
        )
    if vlan_id == 90:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="VLAN 90 is reserved for Security Quarantine and cannot be deleted.",
        )

    driver = get_active_switch_driver(db)
    result = driver.delete_vlan(vlan_id)

    # Delete from DB
    db_rec = db.scalar(select(VlanConfig).where(VlanConfig.vlan_id == vlan_id))
    if db_rec:
        db.delete(db_rec)
        db.commit()

    create_event(
        db=db,
        event_type="vlan_deleted",
        message=f"VLAN {vlan_id} removed from switch by {current_user.role} '{current_user.username}'.",
        device_id=None,
        actor=current_user.username,
    )
    db.commit()

    return {
        "success": True,
        "vlan_id": vlan_id,
        "message": f"VLAN {vlan_id} successfully deleted from switch.",
        "commands_applied": result.get("commands_applied", []),
    }


# -------------------------------------------------------------
# SWITCH PORTS & INTERFACE ASSIGNMENT
# -------------------------------------------------------------

@router.get("/ports")
def list_switch_ports(db: Session = Depends(get_db)):
    """Retrieve all physical switch ports with their assigned VLANs and link status."""
    driver = get_active_switch_driver(db)
    return driver.get_interfaces()


@router.post("/ports/assign")
def assign_port_vlan(
    req: AssignPortVlanRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Assign a physical switch interface to a specific VLAN or configure as Trunk Uplink.
    Directly applies 'switchport access vlan <id>' or 'switchport mode trunk' without console cabling.
    """
    effective_mode = "trunk" if (req.is_trunk or req.mode.lower() == "trunk") else "access"
    driver = get_active_switch_driver(db)
    res = driver.set_port_vlan(
        port_name=req.port_name,
        vlan_id=req.vlan_id,
        mode=effective_mode,
    )

    create_event(
        db=db,
        event_type="switch_port_configured",
        message=(
            f"Switch port '{req.port_name}' configured with VLAN {req.vlan_id} ({effective_mode.upper()} mode) "
            f"by {current_user.role} '{current_user.username}'."
        ),
        device_id=None,
        actor=current_user.username,
    )
    db.commit()

    return res


@router.post("/ports/configure-uplinks")
def configure_switch_uplinks(
    req: ConfigureUplinksRequest | None = None,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Automatically configure the last two ports of the switch chassis as 802.1Q Trunk Uplinks.
    Carries all active VLANs to another switch or core router.
    """
    native_vlan = req.native_vlan if req else 1
    mode = req.mode if req else "trunk"
    driver = get_active_switch_driver(db)
    interfaces = driver.get_interfaces()

    if not interfaces:
        raise HTTPException(status_code=400, detail="No interfaces available on active switch.")

    # Target the last two ports of the switch (e.g. Ports 23 & 24 on a 24-port switch)
    if req and req.ports:
        target_ports = req.ports
    else:
        def get_port_num(p: dict[str, Any]) -> int:
            import re
            m = re.search(r"(\d+)$", p.get("port", ""))
            return int(m.group(1)) if m else 0

        sorted_interfaces = sorted(interfaces, key=get_port_num)
        if len(sorted_interfaces) >= 2:
            target_ports = [sorted_interfaces[-2]["port"], sorted_interfaces[-1]["port"]]
        else:
            target_ports = [sorted_interfaces[-1]["port"]]

    results = []
    for p_name in target_ports:
        r = driver.set_port_vlan(port_name=p_name, vlan_id=native_vlan, mode=mode)
        results.append(r)

    port_names_str = ", ".join(target_ports)
    create_event(
        db=db,
        event_type="switch_uplinks_configured",
        message=(
            f"Switch uplink trunk ports ({port_names_str}) configured as 802.1Q Trunks "
            f"by {current_user.role} '{current_user.username}'."
        ),
        device_id=None,
        actor=current_user.username,
    )
    db.commit()

    return {
        "success": True,
        "ports": target_ports,
        "mode": mode,
        "native_vlan": native_vlan,
        "message": f"Ports {port_names_str} successfully configured as Trunk Uplinks.",
        "results": results,
    }
