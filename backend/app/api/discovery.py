from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..services.discovery import (
    discover_devices,
    save_discovered_devices,
)


router = APIRouter(
    prefix="/discovery",
    tags=["Discovery"],
)


class DiscoveryRequest(BaseModel):
    network: str


@router.post("/scan")
def run_discovery_scan(
    request: DiscoveryRequest,
    db: Session = Depends(get_db),
):
    """
    Discover LAN devices and save them to the NETOPS database.

    Example network:
        192.168.0.0/24
    """

    try:
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
                    "classification_status": (
                        device.classification_status
                    ),
                    "vlan_id": device.vlan_id,
                    "approval_status": (
                        device.approval_status
                    ),
                    "status": device.status,
                }
                for device in saved_devices
            ],
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Discovery scan failed: {exc}",
        ) from exc
