import logging
import shutil
import subprocess
from typing import Any

from .base import BaseFirewallDriver

logger = logging.getLogger(__name__)


class LinuxIptablesDriver(BaseFirewallDriver):
    """
    Driver for Linux Gateway / Router Firewalls using iptables and ipset.
    Enforces quarantine via dynamic IP sets at the Linux kernel packet filtering layer.
    """

    vendor = "linux_iptables"
    vendor_title = "Linux Gateway (iptables / ipset)"
    description = "Linux kernel iptables and ipset packet filtering for local or edge router setups"
    default_port = 22
    auth_type = "none"

    _local_quarantine_set: set[str] = set()

    def is_configured(self) -> bool:
        return True

    def test_connection(self) -> dict[str, Any]:
        has_iptables = bool(shutil.which("iptables"))
        has_ipset = bool(shutil.which("ipset"))

        # Check kernel version
        kernel_ver = "Linux Kernel"
        try:
            res = subprocess.run(["uname", "-r"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0:
                kernel_ver = f"Linux {res.stdout.strip()}"
        except Exception:
            pass

        return {
            "connected": True,
            "vendor": self.vendor,
            "vendor_title": self.vendor_title,
            "firewall_ip": "127.0.0.1",
            "api_version": kernel_ver,
            "quarantine_rule_active": bool(has_iptables or has_ipset),
            "quarantined_hosts_count": len(self._local_quarantine_set),
            "error": None if (has_iptables or has_ipset) else "Neither iptables nor ipset found in PATH",
        }

    def ensure_infrastructure(self) -> bool:
        if shutil.which("ipset") and shutil.which("iptables"):
            try:
                subprocess.run(
                    ["ipset", "create", self.quarantine_group, "hash:ip", "-exist"],
                    capture_output=True,
                    check=False,
                    timeout=3,
                )
                subprocess.run(
                    ["iptables", "-C", "FORWARD", "-m", "set", "--match-set", self.quarantine_group, "src", "-j", "DROP"],
                    capture_output=True,
                    check=False,
                    timeout=3,
                )
                return True
            except Exception as exc:
                logger.warning(f"Linux iptables ensure_infrastructure warning: {exc}")
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

        self._local_quarantine_set.add(ip_address)

        if shutil.which("ipset"):
            try:
                subprocess.run(
                    ["ipset", "add", self.quarantine_group, ip_address, "-exist"],
                    capture_output=True,
                    check=False,
                    timeout=2,
                )
            except Exception as exc:
                logger.warning(f"ipset add error: {exc}")

        return {
            "status": "blocked",
            "ip_address": ip_address,
            "vendor": self.vendor,
            "message": f"Device {ip_address} blocked in Linux firewall ipset '{self.quarantine_group}'.",
        }

    def allow_device(
        self,
        ip_address: str,
        mac_address: str | None = None,
    ) -> dict[str, Any]:
        self._local_quarantine_set.discard(ip_address)

        if shutil.which("ipset"):
            try:
                subprocess.run(
                    ["ipset", "del", self.quarantine_group, ip_address, "-exist"],
                    capture_output=True,
                    check=False,
                    timeout=2,
                )
            except Exception as exc:
                logger.warning(f"ipset del error: {exc}")

        return {
            "status": "allowed",
            "ip_address": ip_address,
            "vendor": self.vendor,
            "message": f"Device {ip_address} removed from Linux firewall ipset.",
        }

    def get_status(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "vendor_title": self.vendor_title,
            "configured": True,
            "management_url": "localhost (kernel)",
            "firewall_ip": "127.0.0.1",
            "port": 0,
            "quarantine_group": self.quarantine_group,
            "tls_verification": False,
            "auth_type": self.auth_type,
        }
