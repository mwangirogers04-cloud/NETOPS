from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from ..database import get_db
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


@router.post("/scan")
def run_discovery_scan(
    request: DiscoveryRequest,
    db: Session = Depends(get_db),
):
    """
    Discover LAN / WLAN devices and save them to the NETOPS database.

    Example network:
        192.168.0.0/24
    """

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
            )
        else:
            discovered_devices = discover_devices(
                request.network
            )
            saved_devices = save_discovered_devices(
                discovered_devices,
                db,
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
