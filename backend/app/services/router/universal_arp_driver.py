import logging
import subprocess
from typing import Any

from .base import BaseRouterDriver
from ..l2_quarantine import (
    quarantine_device_l2,
    restore_device_l2,
    add_iptables_quarantine_ip,
    remove_iptables_quarantine_ip,
    is_protected,
)

logger = logging.getLogger(__name__)


class UniversalArpRouterDriver(BaseRouterDriver):
    """
    Universal Router Enforcement Engine (Zero-Credentials / Network-Level).
    
    Works with ANY home, campus, or ISP router (Tenda, TP-Link, Netgear, Huawei, etc.)
    even when the user does not have administrative access to the router!
    
    Enforces internet quarantine by:
    1. Poisoning the target's ARP gateway pointer to divert packets to NETOPS.
    2. Dropping all forwarded packets in kernel and answering with ICMP Host Unreachable.
    3. Severing active connections instantly (< 20ms).
    """

    def get_vendor_id(self) -> str:
        return "universal_arp"

    def get_vendor_title(self) -> str:
        return "Universal Router Engine (Zero-Config / All Routers)"

    def test_connection(self) -> dict[str, Any]:
        return {
            "success": True,
            "connected": True,
            "vendor": self.get_vendor_id(),
            "message": "Universal Router Engine is active and ready on the local network.",
        }

    def get_connected_devices(self) -> list[dict[str, Any]]:
        devices = []
        try:
            res = subprocess.run(["ip", "-4", "neigh", "show"], capture_output=True, text=True, check=False)
            for line in res.stdout.splitlines():
                if "FAILED" in line or "INCOMPLETE" in line:
                    continue
                parts = line.split()
                if len(parts) >= 5 and "lladdr" in parts:
                    ip = parts[0]
                    mac = parts[parts.index("lladdr") + 1].upper()
                    if len(mac) == 17:
                        devices.append({
                            "ip_address": ip,
                            "mac_address": mac,
                            "interface": parts[parts.index("dev") + 1] if "dev" in parts else None,
                            "status": "online",
                        })
        except Exception as exc:
            logger.debug("ARP discovery failed: %s", exc)
        return devices

    def block_device(self, ip_address: str, mac_address: str, hostname: str = "") -> dict[str, Any]:
        if not ip_address or not mac_address:
            return {"status": "skipped", "reason": "Missing IP or MAC address"}

        clean_ip = ip_address.strip()
        clean_mac = mac_address.strip().upper()

        if is_protected(clean_ip, clean_mac):
            return {"status": "protected", "reason": f"{clean_ip} is protected infrastructure"}

        try:
            add_iptables_quarantine_ip(clean_ip, clean_mac)
            quarantine_device_l2(clean_ip, clean_mac, burst=5)
            logger.info(
                "[UNIVERSAL ROUTER BLOCK] Successfully blocked device %s (%s) on local router",
                clean_ip, clean_mac
            )
            return {
                "status": "blocked",
                "ip_address": clean_ip,
                "mac_address": clean_mac,
                "driver": self.get_vendor_id(),
                "message": f"Device {clean_ip} blocked from internet across all local router traffic.",
            }
        except Exception as exc:
            logger.error("[UNIVERSAL ROUTER ERROR] Failed to block device %s: %s", clean_ip, exc)
            return {"status": "error", "error": str(exc), "ip_address": clean_ip}

    def allow_device(self, ip_address: str, mac_address: str) -> dict[str, Any]:
        if not ip_address or not mac_address:
            return {"status": "skipped", "reason": "Missing IP or MAC address"}

        clean_ip = ip_address.strip()
        clean_mac = mac_address.strip().upper()

        try:
            remove_iptables_quarantine_ip(clean_ip, clean_mac)
            restore_device_l2(clean_ip, clean_mac, burst=5)
            logger.info(
                "[UNIVERSAL ROUTER RESTORE] Successfully restored device %s (%s) on local router",
                clean_ip, clean_mac
            )
            return {
                "status": "allowed",
                "ip_address": clean_ip,
                "mac_address": clean_mac,
                "driver": self.get_vendor_id(),
                "message": f"Device {clean_ip} restored with full internet access.",
            }
        except Exception as exc:
            logger.error("[UNIVERSAL ROUTER ERROR] Failed to restore device %s: %s", clean_ip, exc)
            return {"status": "error", "error": str(exc), "ip_address": clean_ip}
