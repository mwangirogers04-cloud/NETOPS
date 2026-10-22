import logging
from typing import Any
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...config import settings
from ...models.firewall_config import FirewallConfig
from .base import BaseFirewallDriver
from .cisco_firewall_driver import CiscoFirewallDriver
from .enterprise_drivers import (
    ArubaGatewayDriver,
    CheckPointDriver,
    HuaweiUSGDriver,
    JuniperSRXDriver,
    PaloAltoDriver,
    SonicWallDriver,
    UbiquitiUniFiDriver,
    WatchGuardDriver,
)
from .fortinet_driver import FortinetDriver
from .linux_iptables_driver import LinuxIptablesDriver
from .mikrotik_driver import MikrotikDriver
from .pfsense_driver import PfSenseDriver
from .simulation_driver import SimulationDriver
from .sophos_driver import SophosDriver

logger = logging.getLogger(__name__)

VENDOR_DRIVERS: dict[str, type[BaseFirewallDriver]] = {
    "sophos": SophosDriver,
    "fortinet": FortinetDriver,
    "fortigate": FortinetDriver,
    "palo_alto": PaloAltoDriver,
    "checkpoint": CheckPointDriver,
    "mikrotik": MikrotikDriver,
    "pfsense": PfSenseDriver,
    "cisco_asa": CiscoFirewallDriver,
    "juniper_srx": JuniperSRXDriver,
    "sonicwall": SonicWallDriver,
    "watchguard": WatchGuardDriver,
    "ubiquiti": UbiquitiUniFiDriver,
    "aruba": ArubaGatewayDriver,
    "huawei_usg": HuaweiUSGDriver,
    "linux_iptables": LinuxIptablesDriver,
    "simulation": SimulationDriver,
}

VENDOR_METADATA = [
    {
        "id": "sophos",
        "name": "Sophos XG/XGS (SFOS)",
        "icon": "🛡️",
        "description": "Sophos Next-Gen Firewall using SFOS WebConsole XML API controller",
        "default_port": 4444,
        "auth_type": "credentials",
        "url_placeholder": "https://192.168.0.10:4444",
        "requires_username": True,
        "requires_password": True,
        "requires_api_key": False,
    },
    {
        "id": "fortinet",
        "name": "Fortinet FortiGate (FortiOS)",
        "icon": "🏰",
        "description": "Fortinet FortiGate enterprise firewall using FortiOS REST API & Address Groups",
        "default_port": 443,
        "auth_type": "both",
        "url_placeholder": "https://192.168.0.1:443",
        "requires_username": True,
        "requires_password": True,
        "requires_api_key": True,
    },
    {
        "id": "palo_alto",
        "name": "Palo Alto Networks (PAN-OS)",
        "icon": "🔥",
        "description": "Palo Alto PA-Series & VM-Series NGFW using PAN-OS XML/REST API & Dynamic Address Groups",
        "default_port": 443,
        "auth_type": "both",
        "url_placeholder": "https://192.168.1.1",
        "requires_username": True,
        "requires_password": True,
        "requires_api_key": True,
    },
    {
        "id": "checkpoint",
        "name": "Check Point Quantum (Gaia)",
        "icon": "♟️",
        "description": "Check Point Quantum Security Gateway & SmartConsole Management Web API",
        "default_port": 443,
        "auth_type": "both",
        "url_placeholder": "https://192.168.1.10",
        "requires_username": True,
        "requires_password": True,
        "requires_api_key": True,
    },
    {
        "id": "mikrotik",
        "name": "MikroTik RouterOS",
        "icon": "🌐",
        "description": "MikroTik RouterBOARD & CCR routers using native RouterOS REST API",
        "default_port": 443,
        "auth_type": "credentials",
        "url_placeholder": "https://192.168.0.11",
        "requires_username": True,
        "requires_password": True,
        "requires_api_key": False,
    },
    {
        "id": "pfsense",
        "name": "pfSense / OPNsense",
        "icon": "🧱",
        "description": "pfSense & OPNsense open-source firewalls using REST API & alias tables",
        "default_port": 443,
        "auth_type": "both",
        "url_placeholder": "https://192.168.1.1",
        "requires_username": True,
        "requires_password": True,
        "requires_api_key": True,
    },
    {
        "id": "cisco_asa",
        "name": "Cisco ASA / Firepower (FTD)",
        "icon": "🦅",
        "description": "Cisco ASA and Secure Firewall Threat Defense using ASA REST API / FMC",
        "default_port": 443,
        "auth_type": "credentials",
        "url_placeholder": "https://192.168.1.254",
        "requires_username": True,
        "requires_password": True,
        "requires_api_key": False,
    },
    {
        "id": "juniper_srx",
        "name": "Juniper Networks SRX (Junos)",
        "icon": "🌲",
        "description": "Juniper SRX Series Services Gateways using Junos REST / NETCONF API",
        "default_port": 3000,
        "auth_type": "credentials",
        "url_placeholder": "https://192.168.1.250:3000",
        "requires_username": True,
        "requires_password": True,
        "requires_api_key": False,
    },
    {
        "id": "sonicwall",
        "name": "SonicWall NSa / TZ (SonicOS)",
        "icon": "⚡",
        "description": "SonicWall Next-Gen Firewalls using SonicOS 7 REST API address object groups",
        "default_port": 443,
        "auth_type": "credentials",
        "url_placeholder": "https://192.168.168.168",
        "requires_username": True,
        "requires_password": True,
        "requires_api_key": False,
    },
    {
        "id": "watchguard",
        "name": "WatchGuard Firebox (Fireware)",
        "icon": "🔴",
        "description": "WatchGuard Firebox appliances using Fireware RESTful API blocked sites list",
        "default_port": 8080,
        "auth_type": "both",
        "url_placeholder": "https://10.0.1.1:8080",
        "requires_username": True,
        "requires_password": True,
        "requires_api_key": True,
    },
    {
        "id": "ubiquiti",
        "name": "Ubiquiti UniFi / EdgeRouter",
        "icon": "📡",
        "description": "Ubiquiti UniFi Dream Machine (UDM-Pro / UCG) & EdgeOS Firewall Group API",
        "default_port": 443,
        "auth_type": "both",
        "url_placeholder": "https://192.168.1.1",
        "requires_username": True,
        "requires_password": True,
        "requires_api_key": True,
    },
    {
        "id": "aruba",
        "name": "HPE Aruba Gateway (ArubaOS)",
        "icon": "🟠",
        "description": "HPE Aruba Mobility Conductor & Branch Gateways using ArubaOS REST API",
        "default_port": 4343,
        "auth_type": "credentials",
        "url_placeholder": "https://192.168.1.20:4343",
        "requires_username": True,
        "requires_password": True,
        "requires_api_key": False,
    },
    {
        "id": "huawei_usg",
        "name": "Huawei HiSecEngine USG",
        "icon": "🌺",
        "description": "Huawei USG6000E Series Next-Gen Firewalls using RESTCONF / Northbound API",
        "default_port": 8443,
        "auth_type": "credentials",
        "url_placeholder": "https://192.168.0.254:8443",
        "requires_username": True,
        "requires_password": True,
        "requires_api_key": False,
    },
    {
        "id": "linux_iptables",
        "name": "Linux Gateway (iptables / ipset)",
        "icon": "🐧",
        "description": "Linux kernel packet filtering using iptables, nftables, and ipset on gateway",
        "default_port": 0,
        "auth_type": "none",
        "url_placeholder": "localhost",
        "requires_username": False,
        "requires_password": False,
        "requires_api_key": False,
    },
    {
        "id": "simulation",
        "name": "Standalone (Simulation Mode)",
        "icon": "🧪",
        "description": "Internal mock driver for laboratories, testing, and evaluation",
        "default_port": 0,
        "auth_type": "none",
        "url_placeholder": "simulation://internal",
        "requires_username": False,
        "requires_password": False,
        "requires_api_key": False,
    },
]


def list_supported_vendors() -> list[dict[str, Any]]:
    return VENDOR_METADATA


def create_driver_instance(
    vendor: str,
    management_url: str = "",
    api_key: str | None = None,
    username: str | None = None,
    password: str | None = None,
    verify_tls: bool = False,
    quarantine_group: str = "NETOPS_Quarantine",
    quarantine_rule: str = "NETOPS_Quarantine_Block",
    extra_settings: str | None = None,
) -> BaseFirewallDriver:
    driver_cls = VENDOR_DRIVERS.get(vendor.lower(), SimulationDriver)
    return driver_cls(
        management_url=management_url,
        api_key=api_key,
        username=username,
        password=password,
        verify_tls=verify_tls,
        quarantine_group=quarantine_group,
        quarantine_rule=quarantine_rule,
        extra_settings=extra_settings,
    )


def get_active_firewall_driver(db: Session | None = None) -> BaseFirewallDriver:
    """
    Retrieve the active firewall driver.
    1. If a FirewallConfig with is_active=True exists in DB, instantiate and return it.
    2. Otherwise, if Sophos settings are configured in config.py / .env, use SophosDriver.
    3. Otherwise, return SimulationDriver.
    """
    if db is not None:
        try:
            active_cfg = db.scalar(
                select(FirewallConfig).where(FirewallConfig.is_active == True).limit(1)
            )
            if active_cfg:
                return create_driver_instance(
                    vendor=active_cfg.vendor,
                    management_url=active_cfg.management_url or "",
                    api_key=active_cfg.api_key,
                    username=active_cfg.username,
                    password=active_cfg.password,
                    verify_tls=active_cfg.verify_tls,
                    quarantine_group=active_cfg.quarantine_group,
                    quarantine_rule=active_cfg.quarantine_rule,
                    extra_settings=active_cfg.extra_settings,
                )
        except Exception as exc:
            logger.warning(f"Failed to query active FirewallConfig: {exc}")

    # Fallback to Sophos from settings if configured
    if settings.sophos_base_url and settings.sophos_username and settings.sophos_password:
        return SophosDriver(
            management_url=settings.sophos_base_url,
            username=settings.sophos_username,
            password=settings.sophos_password,
            verify_tls=settings.sophos_verify_tls,
        )

    # Default fallback
    return SimulationDriver()


def probe_firewall_connection(
    vendor: str,
    management_url: str = "",
    api_key: str | None = None,
    username: str | None = None,
    password: str | None = None,
    verify_tls: bool = False,
    quarantine_group: str = "NETOPS_Quarantine",
) -> dict[str, Any]:
    driver = create_driver_instance(
        vendor=vendor,
        management_url=management_url,
        api_key=api_key,
        username=username,
        password=password,
        verify_tls=verify_tls,
        quarantine_group=quarantine_group,
    )
    return driver.test_connection()


# Backward-compatible alias
test_firewall_configuration = probe_firewall_connection
