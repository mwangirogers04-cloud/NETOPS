from typing import Any
from urllib.parse import urlparse

from ...config import settings
from ..sophos_enforcement import (
    ensure_sophos_infrastructure,
    is_sophos_configured,
    sophos_allow_device,
    sophos_block_device,
    sophos_test_connection,
)
from .base import BaseFirewallDriver


class SophosDriver(BaseFirewallDriver):
    """
    Driver for Sophos XG / XGS Series Firewalls running SFOS.
    Uses the SFOS WebConsole XML API (TCP 4444) for host/group management
    and top-drop quarantine rule enforcement.
    """

    vendor = "sophos"
    vendor_title = "Sophos XG/XGS (SFOS)"
    description = "Sophos XG & XGS Next-Gen Firewall XML API controller integration"
    default_port = 4444
    auth_type = "credentials"

    def is_configured(self) -> bool:
        if self.management_url and self.username and self.password:
            return True
        return is_sophos_configured()

    def test_connection(self) -> dict[str, Any]:
        res = sophos_test_connection()
        res["vendor"] = self.vendor
        res["vendor_title"] = self.vendor_title
        return res

    def ensure_infrastructure(self) -> bool:
        return ensure_sophos_infrastructure()

    def block_device(
        self,
        ip_address: str,
        hostname: str | None = None,
        mac_address: str | None = None,
    ) -> dict[str, Any]:
        res = sophos_block_device(ip_address, hostname)
        res["vendor"] = self.vendor
        return res

    def allow_device(
        self,
        ip_address: str,
        mac_address: str | None = None,
    ) -> dict[str, Any]:
        res = sophos_allow_device(ip_address)
        res["vendor"] = self.vendor
        return res

    def get_status(self) -> dict[str, Any]:
        url = self.management_url or settings.sophos_base_url
        user = self.username or settings.sophos_username
        parsed = urlparse(url) if url else None
        return {
            "vendor": self.vendor,
            "vendor_title": self.vendor_title,
            "configured": self.is_configured(),
            "management_url": url,
            "firewall_ip": parsed.hostname if parsed else None,
            "port": parsed.port if parsed else self.default_port,
            "username": user,
            "tls_verification": self.verify_tls if self.management_url else settings.sophos_verify_tls,
            "auth_type": self.auth_type,
        }
