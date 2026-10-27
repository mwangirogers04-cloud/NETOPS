"""
802.1X / FreeRADIUS Dynamic Port Assignment & MAC Authentication Bypass (MAB) Service
=====================================================================================
Generates FreeRADIUS server configurations and RFC 2868 / RFC 3580 compliant
dynamic VLAN steering attributes (Tunnel-Type, Tunnel-Medium-Type, Tunnel-Private-Group-Id)
based on NETOPS device approval state and zero-trust policy.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.device import Device
from ..models.switch_config import SwitchConfig
from ..services.vlan_policy import get_vlan_for_device_type

logger = logging.getLogger("netops.radius")

RADIUS_CONFIG_PATH = Path(__file__).resolve().parents[2] / "radius_settings.json"


def get_radius_settings() -> dict[str, Any]:
    """Retrieve active FreeRADIUS and 802.1X MAB steering configuration."""
    defaults = {
        "enabled": True,
        "auth_port": 1812,
        "acct_port": 1813,
        "shared_secret": "netopsRadiusKey123!",
        "quarantine_vlan": 90,
        "mab_format": "lowercase_nodelim",  # lowercase_nodelim (aabbccddeeff), colon (aa:bb:cc:dd:ee:ff), hyphen (aa-bb-cc-dd-ee-ff), cisco (aabb.ccdd.eeff)
        "default_unregistered_policy": "quarantine",  # "quarantine" (assign VLAN 90) or "reject" (drop port)
        "auto_sync_enabled": True,
        "last_sync_at": None,
    }
    if RADIUS_CONFIG_PATH.exists():
        try:
            saved = json.loads(RADIUS_CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(saved, dict):
                defaults.update({k: v for k, v in saved.items() if v is not None})
        except Exception as exc:
            logger.warning(f"Failed to read radius_settings.json: {exc}")
    return defaults


def save_radius_settings(new_cfg: dict[str, Any]) -> dict[str, Any]:
    """Persist FreeRADIUS settings to disk."""
    current = get_radius_settings()
    for k in current.keys():
        if k in new_cfg and new_cfg[k] is not None:
            current[k] = new_cfg[k]
    RADIUS_CONFIG_PATH.write_text(json.dumps(current, indent=2), encoding="utf-8")
    return current


def format_mac_for_radius(mac: str, fmt: str = "lowercase_nodelim") -> str:
    """Format a standard MAC address according to switch vendor MAB RADIUS convention."""
    clean = re.sub(r"[^0-9a-fA-F]", "", mac or "").lower()
    if len(clean) != 12:
        return (mac or "").lower()

    if fmt == "colon":
        return ":".join(clean[i : i + 2] for i in range(0, 12, 2))
    elif fmt == "hyphen":
        return "-".join(clean[i : i + 2] for i in range(0, 12, 2))
    elif fmt == "cisco":
        return f"{clean[0:4]}.{clean[4:8]}.{clean[8:12]}"
    elif fmt == "uppercase_nodelim":
        return clean.upper()
    return clean  # default: lowercase_nodelim (e.g. aabbccddeeff)


def resolve_device_radius_vlan(device: Device) -> tuple[int, str]:
    """
    Determine the target dynamic VLAN and policy decision for an endpoint.
    Returns (vlan_id, reason).
    """
    # Quarantined or rejected devices
    if device.approval_status == "rejected" or device.enforcement_status in ("quarantined", "isolated"):
        return 90, "Endpoint is quarantined/isolated in VLAN 90 quarantine sandbox."

    # Pending devices
    if device.approval_status == "pending":
        return 90, "Endpoint pending administrator approval; confined to VLAN 90."

    # Approved devices: verify internet or target department VLAN
    if device.vlan_id and device.vlan_id != 90:
        return device.vlan_id, f"Approved endpoint explicitly steered to VLAN {device.vlan_id}."

    target = get_vlan_for_device_type(device.device_type)
    if target and target != 90:
        return target, f"Approved endpoint dynamically assigned to VLAN {target} based on device type '{device.device_type}'."

    return 20, "Approved endpoint defaulted to Computer/Data VLAN 20."


def generate_freeradius_users_config(db: Session) -> str:
    """
    Generate complete FreeRADIUS 'users' dictionary file with RFC 2868 / 3580
    Tunnel-Type, Tunnel-Medium-Type, and Tunnel-Private-Group-Id dynamic steering attributes.
    """
    cfg = get_radius_settings()
    fmt = cfg.get("mab_format", "lowercase_nodelim")
    quarantine_vlan = cfg.get("quarantine_vlan", 90)

    devices = list(db.scalars(select(Device).order_by(Device.id)).all())

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# ===================================================================",
        f"# NETOPS 802.1X / MAC Authentication Bypass (MAB) User Dictionary",
        f"# Generated: {now_utc}",
        f"# Active Inventory Endpoints: {len(devices)}",
        "# Compatible with FreeRADIUS 3.x / Cisco Catalyst / Aruba / MikroTik",
        "# RFC 2868 & RFC 3580 Dynamic VLAN Steering Attributes",
        "# ===================================================================",
        "",
    ]

    for dev in devices:
        radius_user = format_mac_for_radius(dev.mac_address, fmt)
        vlan_id, reason = resolve_device_radius_vlan(dev)

        lines.append(f"# Device: {dev.hostname or 'Unknown'} ({dev.ip_address or 'No IP'}) | Type: {dev.device_type or 'unknown'}")
        lines.append(f"# Status: {dev.approval_status.upper()} | Enforcement: {dev.enforcement_status.upper()}")
        lines.append(f"# Reason: {reason}")
        lines.append(f'{radius_user} Cleartext-Password := "{radius_user}"')
        lines.append(f"\tTunnel-Type = 13,")
        lines.append(f"\tTunnel-Medium-Type = 6,")
        lines.append(f'\tTunnel-Private-Group-Id = "{vlan_id}",')
        lines.append(f'\tReply-Message = "NETOPS: Steered to VLAN {vlan_id} ({reason})"')
        lines.append("")

    # Default fallback for unregistered rogue endpoints
    unreg_policy = cfg.get("default_unregistered_policy", "quarantine")
    lines.append("# --- Default Fallback for Unregistered / Rogue LAN Devices ---")
    if unreg_policy == "reject":
        lines.append("DEFAULT\tAuth-Type := Reject")
        lines.append('\tReply-Message = "NETOPS Zero-Trust: Unregistered endpoint rejected."')
    else:
        lines.append("DEFAULT\tAuth-Type := Accept")
        lines.append(f"\tTunnel-Type = 13,")
        lines.append(f"\tTunnel-Medium-Type = 6,")
        lines.append(f'\tTunnel-Private-Group-Id = "{quarantine_vlan}",')
        lines.append(f'\tReply-Message = "NETOPS Zero-Trust: Rogue device isolated to VLAN {quarantine_vlan}."')

    return "\n".join(lines) + "\n"


def generate_freeradius_clients_config(db: Session) -> str:
    """
    Generate FreeRADIUS 'clients.conf' with NAS client definitions
    for all active Cisco/Aruba/MikroTik switches and firewalls.
    """
    cfg = get_radius_settings()
    shared_secret = cfg.get("shared_secret", "netopsRadiusKey123!")
    switches = list(db.scalars(select(SwitchConfig)).all())

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# ===================================================================",
        f"# NETOPS FreeRADIUS clients.conf - Network Access Servers (NAS)",
        f"# Generated: {now_utc}",
        "# ===================================================================",
        "",
        "# Localhost Gateway / Test Client",
        "client localhost {",
        "\tipv4address = 127.0.0.1",
        f'\tsecret = "{shared_secret}"',
        "\tnastype = other",
        "}",
        "",
    ]

    for sw in switches:
        ip = sw.management_ip.strip() if sw.management_ip else None
        if not ip:
            continue

        nastype = "cisco" if "cisco" in sw.vendor.lower() else "other"
        lines.append(f"# Switch: {sw.name} ({sw.vendor})")
        lines.append(f"client switch_{sw.id} {{")
        lines.append(f"\tipv4address = {ip}")
        lines.append(f'\tsecret = "{shared_secret}"')
        lines.append(f"\tnastype = {nastype}")
        lines.append(f'\tshortname = "{re.sub(r"[^a-zA-Z0-9_]", "_", sw.name)}"')
        lines.append("}")
        lines.append("")

    return "\n".join(lines) + "\n"


def simulate_radius_auth(
    db: Session,
    mac_address: str,
    nas_ip: str | None = None,
) -> dict[str, Any]:
    """
    Simulate a live RADIUS 802.1X / MAC Authentication Bypass (MAB) Access-Request
    from a switch port and calculate the exact RADIUS Access-Accept / Access-Reject
    response and returned RFC 2868 / 3580 dynamic VLAN steering attributes.
    """
    cfg = get_radius_settings()
    fmt = cfg.get("mab_format", "lowercase_nodelim")
    clean_mac = (mac_address or "").strip().lower()

    # Find device in inventory
    device = db.scalar(select(Device).where(Device.mac_address.ilike(clean_mac)))
    if not device:
        # Also try without separators
        no_delim = re.sub(r"[^0-9a-fA-F]", "", clean_mac)
        devices = list(db.scalars(select(Device)).all())
        for d in devices:
            if re.sub(r"[^0-9a-fA-F]", "", d.mac_address).lower() == no_delim.lower():
                device = d
                break

    radius_username = format_mac_for_radius(clean_mac, fmt)
    quarantine_vlan = cfg.get("quarantine_vlan", 90)

    if not device:
        unreg_policy = cfg.get("default_unregistered_policy", "quarantine")
        if unreg_policy == "reject":
            return {
                "decision": "Access-Reject",
                "mac_address": clean_mac,
                "radius_username": radius_username,
                "nas_ip": nas_ip or "192.168.0.2",
                "device_registered": False,
                "assigned_vlan": None,
                "reason": "Unknown / Unregistered device rejected by strict zero-trust policy.",
                "radius_attributes": {},
                "simulated_at": datetime.now(timezone.utc).isoformat(),
            }
        else:
            return {
                "decision": "Access-Accept",
                "mac_address": clean_mac,
                "radius_username": radius_username,
                "nas_ip": nas_ip or "192.168.0.2",
                "device_registered": False,
                "assigned_vlan": quarantine_vlan,
                "reason": f"Rogue / Unregistered device auto-quarantined to Isolation VLAN {quarantine_vlan}.",
                "radius_attributes": {
                    "Tunnel-Type": "13 (VLAN)",
                    "Tunnel-Medium-Type": "6 (IEEE-802)",
                    "Tunnel-Private-Group-Id": str(quarantine_vlan),
                    "Reply-Message": f"NETOPS: Unregistered endpoint isolated to VLAN {quarantine_vlan}",
                },
                "simulated_at": datetime.now(timezone.utc).isoformat(),
            }

    vlan_id, reason = resolve_device_radius_vlan(device)
    return {
        "decision": "Access-Accept",
        "mac_address": device.mac_address,
        "radius_username": radius_username,
        "nas_ip": nas_ip or (device.switch_name or "192.168.0.2"),
        "device_registered": True,
        "device_id": device.id,
        "hostname": device.hostname or "Unnamed Endpoint",
        "device_type": device.device_type,
        "approval_status": device.approval_status,
        "enforcement_status": device.enforcement_status,
        "assigned_vlan": vlan_id,
        "reason": reason,
        "radius_attributes": {
            "Tunnel-Type": "13 (VLAN)",
            "Tunnel-Medium-Type": "6 (IEEE-802)",
            "Tunnel-Private-Group-Id": str(vlan_id),
            "Reply-Message": f"NETOPS: Steered to VLAN {vlan_id} ({reason})",
        },
        "simulated_at": datetime.now(timezone.utc).isoformat(),
    }
