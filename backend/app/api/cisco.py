import os

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.device import Device
from ..services.switch_mapping import identify_switch_port_from_mac_table

from ..services.cisco_readonly import (
    get_interface_status,
    get_mac_address_table,
    get_vlan_brief,
)


router = APIRouter(
    prefix="/cisco",
    tags=["Cisco Read-Only"],
)


def check_configuration() -> None:
    """Verify that the required Cisco credentials are configured."""
    if (
        not os.getenv("NETOPS_SWITCH_USERNAME")
        or not os.getenv("NETOPS_SWITCH_PASSWORD")
    ):
        raise HTTPException(
            status_code=503,
            detail=(
                "Cisco access is not configured. "
                "Authorized switch credentials are required."
            ),
        )


@router.get("/status")
def cisco_status():
    """Report Cisco configuration readiness without connecting."""
    import ipaddress

    credentials_configured = bool(
        os.getenv("NETOPS_SWITCH_USERNAME")
        and os.getenv("NETOPS_SWITCH_PASSWORD")
    )

    management_ip = os.getenv("NETOPS_SWITCH_MANAGEMENT_IP", "").strip()
    management_ip_configured = bool(management_ip)

    management_ip_valid = False
    management_ip_approved = False

    if management_ip:
        try:
            normalized_ip = str(ipaddress.ip_address(management_ip))
            management_ip_valid = True

            allowed_ips = {
                item.strip()
                for item in os.getenv(
                    "NETOPS_SWITCH_ALLOWED_IPS", ""
                ).split(",")
                if item.strip()
            }

            management_ip_approved = normalized_ip in allowed_ips
        except ValueError:
            pass

    configured = (
        credentials_configured
        and management_ip_valid
        and management_ip_approved
    )

    return {
        "service": "Cisco read-only integration",
        "configured": configured,
        "credentials_configured": credentials_configured,
        "management_ip_configured": management_ip_configured,
        "management_ip_valid": management_ip_valid,
        "management_ip_approved": management_ip_approved,
        "connection_tested": False,
        "mode": "read-only",
    }




@router.get("/interfaces")
def cisco_interfaces():
    check_configuration()

    management_ip = os.getenv("NETOPS_SWITCH_MANAGEMENT_IP")
    if not management_ip:
        raise HTTPException(
            status_code=503,
            detail="Cisco management IP is not configured.",
        )

    try:
        return {
            "management_ip": management_ip,
            "interfaces": get_interface_status(management_ip),
        }
    except Exception as exc:
        # Log details server-side in a later hardening step;
        # never return raw connection errors to API clients.
        raise HTTPException(
            status_code=502,
            detail="Unable to retrieve Cisco interface status.",
        ) from exc


@router.get("/vlans")
def cisco_vlans():
    check_configuration()

    management_ip = os.getenv("NETOPS_SWITCH_MANAGEMENT_IP")
    if not management_ip:
        raise HTTPException(
            status_code=503,
            detail="Cisco management IP is not configured.",
        )

    try:
        return {
            "management_ip": management_ip,
            "vlans": get_vlan_brief(management_ip),
        }
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Unable to retrieve Cisco VLAN information.",
        ) from exc


@router.get("/mac-table")
def cisco_mac_table():
    check_configuration()

    management_ip = os.getenv("NETOPS_SWITCH_MANAGEMENT_IP")
    if not management_ip:
        raise HTTPException(
            status_code=503,
            detail="Cisco management IP is not configured.",
        )

    try:
        return {
            "management_ip": management_ip,
            "entries": get_mac_address_table(management_ip),
        }
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Unable to retrieve the Cisco MAC address table.",
        ) from exc


@router.get("/devices/{device_id}/port")
def cisco_device_port(
    device_id: int,
    db: Session = Depends(get_db),
):
    """Identify a device's switch port using a read-only MAC table."""

    check_configuration()

    management_ip = os.getenv("NETOPS_SWITCH_MANAGEMENT_IP")
    if not management_ip:
        raise HTTPException(
            status_code=503,
            detail="Cisco management IP is not configured.",
        )

    device = db.scalar(
        select(Device).where(Device.id == device_id)
    )

    if device is None:
        raise HTTPException(
            status_code=404,
            detail="Device not found.",
        )

    try:
        mac_table = get_mac_address_table(management_ip)

        result = identify_switch_port_from_mac_table(
            device=device,
            mac_table=mac_table,
            switch_name=management_ip,
        )

        return {
            "device_id": device.id,
            "mac_address": device.mac_address,
            "management_ip": management_ip,
            "lookup": result,
            "mode": "read-only",
        }

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Unable to identify the device's Cisco switch port.",
        ) from exc
