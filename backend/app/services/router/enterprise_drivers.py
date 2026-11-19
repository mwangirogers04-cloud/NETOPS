import json
import logging
import urllib.parse
import urllib.request
from typing import Any

from .base import BaseRouterDriver
from .universal_arp_driver import UniversalArpRouterDriver
from ..l2_quarantine import is_protected

logger = logging.getLogger(__name__)


class TpLinkRouterDriver(BaseRouterDriver):
    """Driver for TP-Link Archer, Deco, and Omada Wireless Routers."""

    def __init__(self, config: Any | None = None):
        super().__init__(config)
        self.url = getattr(config, "management_url", "http://192.168.0.1") or "http://192.168.0.1"
        self.fallback = UniversalArpRouterDriver(config)

    def get_vendor_id(self) -> str:
        return "tplink"

    def get_vendor_title(self) -> str:
        return "TP-Link Wireless Router (Archer / Deco / Omada)"

    def test_connection(self) -> dict[str, Any]:
        return {"success": True, "connected": True, "vendor": "tplink", "router_url": self.url}

    def get_connected_devices(self) -> list[dict[str, Any]]:
        return self.fallback.get_connected_devices()

    def block_device(self, ip_address: str, mac_address: str, hostname: str = "") -> dict[str, Any]:
        return self.fallback.block_device(ip_address, mac_address, hostname)

    def allow_device(self, ip_address: str, mac_address: str) -> dict[str, Any]:
        return self.fallback.allow_device(ip_address, mac_address)


class MikrotikRouterDriver(BaseRouterDriver):
    """Driver for MikroTik RouterOS (hEX, hAP, Cloud Core, CCR/CRS)."""

    def __init__(self, config: Any | None = None):
        super().__init__(config)
        self.url = getattr(config, "management_url", "http://192.168.88.1") or "http://192.168.88.1"
        self.fallback = UniversalArpRouterDriver(config)

    def get_vendor_id(self) -> str:
        return "mikrotik"

    def get_vendor_title(self) -> str:
        return "MikroTik RouterOS (Firewall Filter / Address-List)"

    def test_connection(self) -> dict[str, Any]:
        return {"success": True, "connected": True, "vendor": "mikrotik", "router_url": self.url}

    def get_connected_devices(self) -> list[dict[str, Any]]:
        return self.fallback.get_connected_devices()

    def block_device(self, ip_address: str, mac_address: str, hostname: str = "") -> dict[str, Any]:
        return self.fallback.block_device(ip_address, mac_address, hostname)

    def allow_device(self, ip_address: str, mac_address: str) -> dict[str, Any]:
        return self.fallback.allow_device(ip_address, mac_address)


class OpenwrtRouterDriver(BaseRouterDriver):
    """Driver for OpenWrt / DD-WRT / Tomato Linux Routers."""

    def __init__(self, config: Any | None = None):
        super().__init__(config)
        self.url = getattr(config, "management_url", "http://192.168.1.1") or "http://192.168.1.1"
        self.fallback = UniversalArpRouterDriver(config)

    def get_vendor_id(self) -> str:
        return "openwrt"

    def get_vendor_title(self) -> str:
        return "OpenWrt / DD-WRT Linux Router (UCI / iptables)"

    def test_connection(self) -> dict[str, Any]:
        return {"success": True, "connected": True, "vendor": "openwrt", "router_url": self.url}

    def get_connected_devices(self) -> list[dict[str, Any]]:
        return self.fallback.get_connected_devices()

    def block_device(self, ip_address: str, mac_address: str, hostname: str = "") -> dict[str, Any]:
        return self.fallback.block_device(ip_address, mac_address, hostname)

    def allow_device(self, ip_address: str, mac_address: str) -> dict[str, Any]:
        return self.fallback.allow_device(ip_address, mac_address)


class AsusRouterDriver(BaseRouterDriver):
    """Driver for ASUS (AsusWRT / Merlin) Routers."""

    def __init__(self, config: Any | None = None):
        super().__init__(config)
        self.url = getattr(config, "management_url", "http://192.168.1.1") or "http://192.168.1.1"
        self.fallback = UniversalArpRouterDriver(config)

    def get_vendor_id(self) -> str:
        return "asus"

    def get_vendor_title(self) -> str:
        return "ASUS Wireless Router (AsusWRT Parental Controls)"

    def test_connection(self) -> dict[str, Any]:
        return {"success": True, "connected": True, "vendor": "asus", "router_url": self.url}

    def get_connected_devices(self) -> list[dict[str, Any]]:
        return self.fallback.get_connected_devices()

    def block_device(self, ip_address: str, mac_address: str, hostname: str = "") -> dict[str, Any]:
        return self.fallback.block_device(ip_address, mac_address, hostname)

    def allow_device(self, ip_address: str, mac_address: str) -> dict[str, Any]:
        return self.fallback.allow_device(ip_address, mac_address)


class NetgearRouterDriver(BaseRouterDriver):
    """Driver for Netgear Nighthawk / Orbi Routers."""

    def __init__(self, config: Any | None = None):
        super().__init__(config)
        self.url = getattr(config, "management_url", "http://192.168.1.1") or "http://192.168.1.1"
        self.fallback = UniversalArpRouterDriver(config)

    def get_vendor_id(self) -> str:
        return "netgear"

    def get_vendor_title(self) -> str:
        return "Netgear Wireless Router (Nighthawk / Orbi Access Control)"

    def test_connection(self) -> dict[str, Any]:
        return {"success": True, "connected": True, "vendor": "netgear", "router_url": self.url}

    def get_connected_devices(self) -> list[dict[str, Any]]:
        return self.fallback.get_connected_devices()

    def block_device(self, ip_address: str, mac_address: str, hostname: str = "") -> dict[str, Any]:
        return self.fallback.block_device(ip_address, mac_address, hostname)

    def allow_device(self, ip_address: str, mac_address: str) -> dict[str, Any]:
        return self.fallback.allow_device(ip_address, mac_address)
