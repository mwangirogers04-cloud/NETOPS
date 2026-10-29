import logging
import os
from typing import Any
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models.switch_config import SwitchConfig
from .base import BaseSwitchDriver, check_switch_reachability, invalidate_switch_reachability
from .cisco_driver import CiscoSwitchDriver
from .cisco_sge_driver import CiscoSgeSwitchDriver
from .enterprise_drivers import (
    AristaSwitchDriver,
    ArubaSwitchDriver,
    DellSwitchDriver,
    DLinkSwitchDriver,
    ExtremeBrocadeSwitchDriver,
    HuaweiSwitchDriver,
    JuniperSwitchDriver,
    MikrotikSwitchDriver,
    NetgearSwitchDriver,
    TpLinkSwitchDriver,
    UbiquitiSwitchDriver,
    ZyxelSwitchDriver,
)
from .simulation_driver import SimulationSwitchDriver

logger = logging.getLogger(__name__)

SWITCH_VENDOR_DRIVERS: dict[str, type[BaseSwitchDriver]] = {
    # Cisco Catalyst & IOS
    "cisco_ios": CiscoSwitchDriver,
    "cisco": CiscoSwitchDriver,
    "cisco_catalyst": CiscoSwitchDriver,
    "cisco_nexus": CiscoSwitchDriver,
    "cisco_xe": CiscoSwitchDriver,
    # Cisco Small Business / SGE
    "cisco_sge": CiscoSgeSwitchDriver,
    "cisco_sge2000": CiscoSgeSwitchDriver,
    "cisco_s300": CiscoSgeSwitchDriver,
    "cisco_s200": CiscoSgeSwitchDriver,
    "sge2000": CiscoSgeSwitchDriver,
    # Ubiquiti
    "ubiquiti": UbiquitiSwitchDriver,
    "ubiquiti_edgeswitch": UbiquitiSwitchDriver,
    "ubiquiti_unifiswitch": UbiquitiSwitchDriver,
    "unifi": UbiquitiSwitchDriver,
    "edgeswitch": UbiquitiSwitchDriver,
    # Juniper
    "juniper": JuniperSwitchDriver,
    "juniper_junos": JuniperSwitchDriver,
    "junos": JuniperSwitchDriver,
    # Arista
    "arista": AristaSwitchDriver,
    "arista_eos": AristaSwitchDriver,
    # Dell EMC
    "dell": DellSwitchDriver,
    "dell_os10": DellSwitchDriver,
    "dell_os6": DellSwitchDriver,
    "dell_powerconnect": DellSwitchDriver,
    # TP-Link
    "tplink": TpLinkSwitchDriver,
    "tplink_jetstream": TpLinkSwitchDriver,
    "omada": TpLinkSwitchDriver,
    # D-Link
    "dlink": DLinkSwitchDriver,
    "dlink_ds": DLinkSwitchDriver,
    # Huawei
    "huawei": HuaweiSwitchDriver,
    "huawei_vrp": HuaweiSwitchDriver,
    # Extreme / Brocade / Ruckus
    "extreme": ExtremeBrocadeSwitchDriver,
    "extreme_exos": ExtremeBrocadeSwitchDriver,
    "brocade": ExtremeBrocadeSwitchDriver,
    "ruckus": ExtremeBrocadeSwitchDriver,
    "ruckus_fastiron": ExtremeBrocadeSwitchDriver,
    # Netgear
    "netgear": NetgearSwitchDriver,
    "netgear_prosafe": NetgearSwitchDriver,
    # Zyxel
    "zyxel": ZyxelSwitchDriver,
    "zyxel_os": ZyxelSwitchDriver,
    # Aruba / HP ProCurve
    "aruba": ArubaSwitchDriver,
    "aruba_procurve": ArubaSwitchDriver,
    "aruba_aoscx": ArubaSwitchDriver,
    "hp_procurve": ArubaSwitchDriver,
    # MikroTik
    "mikrotik": MikrotikSwitchDriver,
    "mikrotik_routeros": MikrotikSwitchDriver,
    "routeros": MikrotikSwitchDriver,
    # Simulation
    "simulation": SimulationSwitchDriver,
}

SUPPORTED_SWITCH_VENDORS = [
    {
        "id": "cisco_sge",
        "name": "Cisco SGE2000 / Small Business Series",
        "icon": "🏢",
        "description": "Cisco SGE2000, SGE2000P, SG300, SG350, SG500 24-Port Gigabit Switches via SSH CLI",
        "default_port": 22,
        "requires_secret": True,
        "default_model": "Cisco SGE2000 24-Port Gigabit Managed Switch",
    },
    {
        "id": "cisco_ios",
        "name": "Cisco Catalyst & IOS-XE",
        "icon": "🌐",
        "description": "Enterprise Cisco Catalyst (2960, 3560, 3850, 9200, 9300) via SSH CLI Netmiko",
        "default_port": 22,
        "requires_secret": True,
        "default_model": "Cisco Catalyst 2960-X",
    },
    {
        "id": "ubiquiti",
        "name": "Ubiquiti Networks (EdgeSwitch & UniFi)",
        "icon": "📶",
        "description": "Ubiquiti EdgeSwitch (ES-24, ES-48) & UniFi Switch (USW-24/48) via SSH CLI",
        "default_port": 22,
        "requires_secret": True,
        "default_model": "Ubiquiti EdgeSwitch 24-Port Gigabit",
    },
    {
        "id": "juniper",
        "name": "Juniper Networks Junos (EX / QFX Series)",
        "icon": "🌲",
        "description": "Juniper EX2200, EX2300, EX3400, EX4300 and QFX switches with candidate commit",
        "default_port": 22,
        "requires_secret": False,
        "default_model": "Juniper EX2300 24-Port Ethernet Switch",
    },
    {
        "id": "arista",
        "name": "Arista Networks EOS",
        "icon": "🛰️",
        "description": "Data center & enterprise Arista 7050, 7150, 7280 switches using EOS CLI",
        "default_port": 22,
        "requires_secret": True,
        "default_model": "Arista 7050SX 24-Port 10G/Gigabit",
    },
    {
        "id": "dell",
        "name": "Dell EMC Networking (PowerConnect & OS10)",
        "icon": "💻",
        "description": "Dell Networking N-Series (N2024, N3048), S-Series (OS10), and PowerConnect",
        "default_port": 22,
        "requires_secret": True,
        "default_model": "Dell EMC Networking N2024 24-Port",
    },
    {
        "id": "tplink",
        "name": "TP-Link JetStream & Omada Managed",
        "icon": "📡",
        "description": "TP-Link JetStream T1600G, T2600G, SG3428, and Omada SDN managed switches",
        "default_port": 22,
        "requires_secret": False,
        "default_model": "TP-Link JetStream SG3428 24-Port",
    },
    {
        "id": "dlink",
        "name": "D-Link Managed Switches (DGS / DES)",
        "icon": "🔷",
        "description": "D-Link DGS-1210, DGS-1510, DGS-3120, and DES series Smart Managed switches",
        "default_port": 22,
        "requires_secret": False,
        "default_model": "D-Link DGS-1210-28 24-Port Gigabit",
    },
    {
        "id": "huawei",
        "name": "Huawei CloudEngine & Quidway (VRP)",
        "icon": "🏮",
        "description": "Huawei VRP enterprise switches (S5700, S6700, CloudEngine) using VRP CLI",
        "default_port": 22,
        "requires_secret": False,
        "default_model": "Huawei S5720-28P Gigabit Switch",
    },
    {
        "id": "extreme",
        "name": "Extreme Networks & Ruckus / Brocade ICX",
        "icon": "💎",
        "description": "Ruckus ICX 7150/7450 and ExtremeXOS Summit series campus switches",
        "default_port": 22,
        "requires_secret": True,
        "default_model": "Ruckus ICX 7150-24 24-Port Gigabit",
    },
    {
        "id": "netgear",
        "name": "Netgear ProSafe Managed Series",
        "icon": "🛡️",
        "description": "Netgear ProSafe M4250, M4300, and GS724T Smart Managed Gigabit switches",
        "default_port": 22,
        "requires_secret": False,
        "default_model": "Netgear ProSafe M4250 24-Port Switch",
    },
    {
        "id": "zyxel",
        "name": "Zyxel Managed Switches (GS / XGS)",
        "icon": "🔶",
        "description": "Zyxel GS1900, GS2210, and XGS series enterprise managed switches",
        "default_port": 22,
        "requires_secret": False,
        "default_model": "Zyxel GS2210-24 24-Port Gigabit",
    },
    {
        "id": "aruba",
        "name": "Aruba CX & HP ProCurve",
        "icon": "⚡",
        "description": "Aruba CX 6000/6200 and legacy HP ProCurve (2920, 2930F, 2530) switches",
        "default_port": 22,
        "requires_secret": False,
        "default_model": "Aruba 2930F 24-Port Gigabit Switch",
    },
    {
        "id": "mikrotik",
        "name": "MikroTik Cloud Router Switch (SwOS/RouterOS)",
        "icon": "🔀",
        "description": "MikroTik CRS3xx & Cloud Smart Switches using Bridge VLAN filtering",
        "default_port": 22,
        "requires_secret": False,
        "default_model": "MikroTik CRS326-24G-2S+RM",
    },
    {
        "id": "simulation",
        "name": "Software Switch Simulator (Netmiko/Cisco Emulation)",
        "icon": "💻",
        "description": "Full in-memory Cisco CLI emulation for testing, labs, and development",
        "default_port": 22,
        "requires_secret": False,
        "default_model": "NETOPS Virtual Switch 24-Port",
    },
]


def list_supported_switch_vendors() -> list[dict[str, Any]]:
    return SUPPORTED_SWITCH_VENDORS


def create_switch_driver(config: SwitchConfig | dict[str, Any] | None) -> BaseSwitchDriver:
    """Instantiate the correct switch driver for a given switch config."""
    if config is None:
        return SimulationSwitchDriver(None)

    if isinstance(config, dict):
        vendor = config.get("vendor", "cisco_ios").lower()
    else:
        vendor = getattr(config, "vendor", "cisco_ios").lower()

    driver_cls = SWITCH_VENDOR_DRIVERS.get(vendor, CiscoSwitchDriver)
    return driver_cls(config)


def get_active_switch_driver(db: Session | None = None) -> BaseSwitchDriver:
    """
    Get the driver for the currently active switch in the database.
    If no active switch is registered in DB, checks environment variables or uses Simulation.
    """
    if db is not None:
        try:
            active_cfg = db.scalar(
                select(SwitchConfig).where(SwitchConfig.is_active == True).limit(1)
            )
            if active_cfg:
                return create_switch_driver(active_cfg)
        except Exception as exc:
            logger.warning("Could not query active switch from DB: %s", exc)

    # Check environment variable NETOPS_SWITCH_MANAGEMENT_IP
    switch_ip = os.getenv("NETOPS_SWITCH_MANAGEMENT_IP")
    if switch_ip:
        mock_cfg = {
            "vendor": "cisco_ios",
            "name": f"Switch ({switch_ip})",
            "management_ip": switch_ip,
            "port": 22,
            "username": os.getenv("NETOPS_SWITCH_USERNAME", "admin"),
            "password": os.getenv("NETOPS_SWITCH_PASSWORD", ""),
            "enable_secret": os.getenv("NETOPS_SWITCH_ENABLE_SECRET", ""),
            "is_active": True,
        }
        return CiscoSwitchDriver(mock_cfg)

    return SimulationSwitchDriver(None)


def probe_switch_connection(
    vendor: str,
    management_ip: str,
    port: int = 22,
    username: str | None = None,
    password: str | None = None,
    enable_secret: str | None = None,
) -> dict[str, Any]:
    """Test reachability and authentication to a switch."""
    invalidate_switch_reachability(management_ip, port)
    mock_cfg = {
        "vendor": vendor,
        "name": f"Test-{management_ip}",
        "management_ip": management_ip,
        "port": port,
        "username": username,
        "password": password,
        "enable_secret": enable_secret,
        "is_active": False,
    }
    driver = create_switch_driver(mock_cfg)
    return driver.test_connection()
