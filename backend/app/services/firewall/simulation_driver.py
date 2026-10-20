from typing import Any

from .base import BaseFirewallDriver


class SimulationDriver(BaseFirewallDriver):
    """
    Standalone / Simulation Driver.
    Emulates firewall isolation behavior for laboratories, demos,
    and environments without an attached hardware firewall.
    """

    vendor = "simulation"
    vendor_title = "Standalone (Simulation Mode)"
    description = "Software simulation mode for labs, evaluation, and test environments"
    default_port = 0
    auth_type = "none"

    _simulated_quarantine: set[str] = set()

    def is_configured(self) -> bool:
        return True

    def test_connection(self) -> dict[str, Any]:
        return {
            "connected": True,
            "vendor": self.vendor,
            "vendor_title": self.vendor_title,
            "firewall_ip": "127.0.0.1",
            "api_version": "NETOPS Simulation Engine 1.0",
            "quarantine_rule_active": True,
            "quarantined_hosts_count": len(self._simulated_quarantine),
            "error": None,
        }

    def ensure_infrastructure(self) -> bool:
        return True

    def block_device(
        self,
        ip_address: str,
        hostname: str | None = None,
        mac_address: str | None = None,
    ) -> dict[str, Any]:
        if self.is_protected_ip(ip_address):
            return {
                "status": "protected",
                "ip_address": ip_address,
                "vendor": self.vendor,
                "reason": f"IP {ip_address} is a protected infrastructure IP and cannot be blocked.",
            }

        self._simulated_quarantine.add(ip_address)
        return {
            "status": "blocked",
            "ip_address": ip_address,
            "vendor": self.vendor,
            "message": f"[Simulation] Device {ip_address} quarantined.",
        }

    def allow_device(
        self,
        ip_address: str,
        mac_address: str | None = None,
    ) -> dict[str, Any]:
        self._simulated_quarantine.discard(ip_address)
        return {
            "status": "allowed",
            "ip_address": ip_address,
            "vendor": self.vendor,
            "message": f"[Simulation] Device {ip_address} unblocked.",
        }

    def get_status(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "vendor_title": self.vendor_title,
            "configured": True,
            "management_url": "simulation://internal",
            "firewall_ip": "127.0.0.1",
            "port": 0,
            "quarantine_group": self.quarantine_group,
            "tls_verification": False,
            "auth_type": self.auth_type,
        }
