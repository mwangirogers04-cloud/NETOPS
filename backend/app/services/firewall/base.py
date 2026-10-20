from abc import ABC, abstractmethod
from typing import Any


PROTECTED_IPS = {
    "127.0.0.1",
    "::1",
    "192.168.0.1",
    "192.168.0.10",
    "192.168.0.13",
    "192.168.0.101",
}


class BaseFirewallDriver(ABC):
    """
    Abstract Base Class for Multi-Vendor Firewall Integrations.
    Standardizes quarantine, unquarantine, reachability testing, and status reporting
    across Sophos, Fortinet, MikroTik, pfSense, Cisco ASA, Linux iptables, etc.
    """

    vendor: str = "base"
    vendor_title: str = "Base Firewall"
    description: str = "Abstract firewall driver"
    default_port: int = 443
    auth_type: str = "credentials"  # "credentials", "api_token", "both", "none"

    def __init__(
        self,
        management_url: str = "",
        api_key: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_tls: bool = False,
        quarantine_group: str = "NETOPS_Quarantine",
        quarantine_rule: str = "NETOPS_Quarantine_Block",
        extra_settings: str | None = None,
    ):
        self.management_url = (management_url or "").strip().rstrip("/")
        self.api_key = (api_key or "").strip()
        self.username = (username or "").strip()
        self.password = (password or "").strip()
        self.verify_tls = verify_tls
        self.quarantine_group = quarantine_group or "NETOPS_Quarantine"
        self.quarantine_rule = quarantine_rule or "NETOPS_Quarantine_Block"
        self.extra_settings = extra_settings

    def is_protected_ip(self, ip_address: str) -> bool:
        """Check if an IP belongs to critical gateway or management infrastructure."""
        return ip_address in PROTECTED_IPS

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True if required configuration (URL, credentials/token) is provided."""
        pass

    @abstractmethod
    def test_connection(self) -> dict[str, Any]:
        """
        Verify network reachability and authentication to the firewall.
        Must return a dict with at least:
          - 'connected': bool
          - 'vendor': str
          - 'firewall_ip': str | None
          - 'api_version': str | None
          - 'quarantine_rule_active': bool
          - 'quarantined_hosts_count': int
          - 'error': str | None
        """
        pass

    @abstractmethod
    def ensure_infrastructure(self) -> bool:
        """Ensure quarantine group/address list and top block rule exist."""
        pass

    @abstractmethod
    def block_device(
        self,
        ip_address: str,
        hostname: str | None = None,
        mac_address: str | None = None,
    ) -> dict[str, Any]:
        """
        Quarantine and block internet access for a device.
        Must return a dict with at least:
          - 'status': 'blocked' | 'protected' | 'simulated' | 'error'
          - 'ip_address': str
          - 'vendor': str
          - 'message': str
        """
        pass

    @abstractmethod
    def allow_device(
        self,
        ip_address: str,
        mac_address: str | None = None,
    ) -> dict[str, Any]:
        """
        Remove a device from quarantine and allow internet access.
        Must return a dict with at least:
          - 'status': 'allowed' | 'simulated' | 'error'
          - 'ip_address': str
          - 'vendor': str
          - 'message': str
        """
        pass

    @abstractmethod
    def get_status(self) -> dict[str, Any]:
        """Return metadata and configuration readiness for this driver."""
        pass

    def get_quarantined_hosts(self) -> list[str]:
        """Return list of currently quarantined IP addresses if supported."""
        return []
