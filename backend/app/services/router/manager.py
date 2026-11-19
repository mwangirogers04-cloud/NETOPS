import logging
import subprocess
from typing import Any
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models.router_config import RouterConfig
from .base import BaseRouterDriver
from .tenda_driver import TendaRouterDriver
from .universal_arp_driver import UniversalArpRouterDriver
from .enterprise_drivers import (
    TpLinkRouterDriver,
    MikrotikRouterDriver,
    OpenwrtRouterDriver,
    AsusRouterDriver,
    NetgearRouterDriver,
)

logger = logging.getLogger(__name__)

ROUTER_VENDOR_DRIVERS: dict[str, type[BaseRouterDriver]] = {
    "universal_arp": UniversalArpRouterDriver,
    "universal": UniversalArpRouterDriver,
    "auto_detect": UniversalArpRouterDriver,
    "tenda": TendaRouterDriver,
    "tendawifi": TendaRouterDriver,
    "tplink": TpLinkRouterDriver,
    "tp_link": TpLinkRouterDriver,
    "omada": TpLinkRouterDriver,
    "mikrotik": MikrotikRouterDriver,
    "routeros": MikrotikRouterDriver,
    "openwrt": OpenwrtRouterDriver,
    "ddwrt": OpenwrtRouterDriver,
    "asus": AsusRouterDriver,
    "asuswrt": AsusRouterDriver,
    "netgear": NetgearRouterDriver,
}

SUPPORTED_ROUTER_VENDORS = [
    {
        "id": "universal_arp",
        "name": "Universal Router Engine (All Routers / Zero-Config)",
        "icon": "🌐",
        "description": "Works with ANY home or office router without credentials. Uses kernel Layer 2 blocking.",
    },
    {
        "id": "tenda",
        "name": "Tenda Wireless Router",
        "icon": "📶",
        "description": "Direct hardware Access Control / Parental Control for Tenda AC, F, Nova, and RX/TX series.",
    },
    {
        "id": "tplink",
        "name": "TP-Link (Archer / Deco / Omada)",
        "icon": "📡",
        "description": "Hardware access control for TP-Link Archer and Omada wireless routers.",
    },
    {
        "id": "mikrotik",
        "name": "MikroTik RouterOS",
        "icon": "🔀",
        "description": "Enterprise MikroTik router firewall filter and address-list quarantine.",
    },
    {
        "id": "openwrt",
        "name": "OpenWrt / DD-WRT",
        "icon": "🐧",
        "description": "OpenWrt / Linux-based routers via UCI / iptables firewall rules.",
    },
    {
        "id": "asus",
        "name": "ASUS (AsusWRT)",
        "icon": "⚡",
        "description": "Hardware Parental Control for ASUS RT and ROG wireless routers.",
    },
    {
        "id": "netgear",
        "name": "Netgear (Nighthawk / Orbi)",
        "icon": "🛡️",
        "description": "Netgear Nighthawk and Orbi Access Control blocking.",
    },
]


def detect_default_gateway_ip() -> str:
    """Determine the local default gateway IP (e.g. 192.168.0.1)."""
    try:
        res = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, check=False)
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "default" and parts[1] == "via":
                return parts[2]
    except Exception:
        pass
    return "192.168.0.1"


def create_router_driver(config: RouterConfig | dict[str, Any] | None) -> BaseRouterDriver:
    """Instantiate the correct router driver for a given configuration."""
    if config is None:
        return UniversalArpRouterDriver(None)

    if isinstance(config, dict):
        vendor = config.get("vendor", "universal_arp").lower()
    else:
        vendor = getattr(config, "vendor", "universal_arp").lower()

    driver_cls = ROUTER_VENDOR_DRIVERS.get(vendor, UniversalArpRouterDriver)
    return driver_cls(config)


def get_active_router_driver(db: Session | None = None) -> BaseRouterDriver:
    """
    Get the active router driver from the database, or auto-detect local gateway.
    """
    if db is not None:
        try:
            active_cfg = db.scalar(
                select(RouterConfig).where(RouterConfig.is_active == True).limit(1)
            )
            if active_cfg:
                return create_router_driver(active_cfg)
        except Exception as exc:
            logger.debug("Could not query active router from DB: %s", exc)

    # Auto-detect default gateway router
    gw_ip = detect_default_gateway_ip()
    mock_cfg = {
        "vendor": "tenda" if gw_ip == "192.168.0.1" else "universal_arp",
        "name": f"Router ({gw_ip})",
        "gateway_ip": gw_ip,
        "management_url": f"http://{gw_ip}",
        "is_active": True,
    }
    return create_router_driver(mock_cfg)


def list_supported_router_vendors() -> list[dict[str, Any]]:
    return SUPPORTED_ROUTER_VENDORS
