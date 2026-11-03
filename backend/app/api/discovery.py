import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.user import User
from ..services.auth_service import get_optional_current_user
from ..services.discovery import (
    detect_local_subnets,
    discover_devices,
    save_discovered_devices,
)


router = APIRouter(
    prefix="/discovery",
    tags=["Discovery"],
)


@router.get("/local-subnets")
def get_local_subnets():
    """
    Detect local network subnets on host interfaces to provide
    zero-configuration LAN scanning.
    """
    return detect_local_subnets()


class DiscoveryRequest(BaseModel):
    network: str
    interface: str | None = None

    @field_validator("network")
    @classmethod
    def validate_network(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Network range cannot be empty.")
        return value


class AgentDeviceItem(BaseModel):
    mac_address: str
    ip_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    device_type: str | None = None
    network_interface: str | None = None


class AgentSyncRequest(BaseModel):
    network: str
    interface: str | None = None
    devices: list[AgentDeviceItem]


@router.post("/scan")
def run_discovery_scan(
    request: DiscoveryRequest,
    current_user: User | None = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    """
    Discover LAN / WLAN devices on the host server's local interfaces and save them
    as infrastructure devices.
    """
    if current_user:
        is_admin = (
            current_user.role in ("admin", "super_admin")
            or current_user.username.lower() in ("developer", "admin")
        )
        if not is_admin:
            raise HTTPException(
                status_code=403,
                detail="Standard users cannot trigger server-side hardware discovery on the host server. To scan your own network, run the NetOps Client Scanner Probe (netops_probe.py) on your local computer.",
            )

    # Server-side physical scan is strictly infrastructure (admin owner)
    owner_id = 1

    try:
        clean_iface = (
            request.interface.strip()
            if request.interface and request.interface.strip() and request.interface.strip().lower() != "all"
            else None
        )
        if clean_iface:
            discovered_devices = discover_devices(
                request.network,
                interface=clean_iface,
            )
            saved_devices = save_discovered_devices(
                discovered_devices,
                db,
                scanned_interface=clean_iface,
                owner_id=owner_id,
            )
        else:
            discovered_devices = discover_devices(
                request.network
            )
            saved_devices = save_discovered_devices(
                discovered_devices,
                db,
                owner_id=owner_id,
            )

        return {
            "status": "completed",
            "network": request.network,
            "interface": clean_iface or "all",
            "devices_discovered": len(
                discovered_devices
            ),
            "devices_processed": len(
                saved_devices
            ),
            "devices": [
                {
                    "id": device.id,
                    "ip_address": device.ip_address,
                    "mac_address": device.mac_address,
                    "hostname": device.hostname,
                    "vendor": device.vendor,
                    "device_type": device.device_type,
                    "network_interface": (
                        getattr(device, "network_interface", None)
                        if isinstance(getattr(device, "network_interface", None), str)
                        else clean_iface
                    ),
                    "classification_status": (
                        device.classification_status
                    ),
                    "vlan_id": device.vlan_id,
                    "approval_status": (
                        device.approval_status
                    ),
                    "status": device.status,
                    "internet_access_authorized": getattr(
                        device, "internet_access_authorized", False
                    ),
                    "enforcement_status": getattr(
                        device, "enforcement_status", "unknown"
                    ),
                }
                for device in saved_devices
            ],
        }


    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="Invalid network range. Provide a valid IPv4 CIDR range, such as 192.168.1.0/24.",
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Discovery scan failed due to an internal error.",
        ) from exc


@router.post("/agent-sync")
def sync_agent_devices(
    request: AgentSyncRequest,
    current_user: User | None = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    """
    Receives scan results from a remote user's client-side scan probe,
    storing and scoping them under the user's isolated account.
    """
    owner_id = current_user.id if current_user else 1
    raw_devices = [d.model_dump() for d in request.devices]
    clean_iface = request.interface.strip() if request.interface and request.interface.strip() else None
    saved = save_discovered_devices(
        raw_devices,
        db=db,
        scanned_interface=clean_iface,
        owner_id=owner_id,
    )
    return {
        "status": "completed",
        "network": request.network,
        "owner_id": owner_id,
        "devices_discovered": len(raw_devices),
        "devices_saved": len(saved),
    }


@router.get("/probe-script")
def download_probe_script():
    """
    Serves the standalone NetOps LAN probe script for remote clients to download.
    """
    probe_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../agent/netops_probe.py"))
    if not os.path.exists(probe_path):
        raise HTTPException(status_code=404, detail="Probe script not found.")
    return FileResponse(
        probe_path,
        media_type="text/x-python",
        filename="netops_probe.py",
    )

