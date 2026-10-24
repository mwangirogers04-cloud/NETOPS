import logging
import os
from typing import Any
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models.switch_config import SwitchConfig
from .base import BaseSwitchDriver
from .cisco_driver import CiscoSwitchDriver
from .cisco_sge_driver import CiscoSgeSwitchDriver
from .enterprise_drivers import ArubaSwitchDriver, MikrotikSwitchDriver
from .simulation_driver import SimulationSwitchDriver

logger = logging.getLogger(__name__)

SWITCH_VENDOR_DRIVERS: dict[str, type[BaseSwitchDriver]] = {
    "cisco_ios": CiscoSwitchDriver,
    "cisco": CiscoSwitchDriver,
    "cisco_catalyst": CiscoSwitchDriver,
    "cisco_nexus": CiscoSwitchDriver,
    "cisco_sge": CiscoSgeSwitchDriver,
    "cisco_sge2000": CiscoSgeSwitchDriver,
    "cisco_s300": CiscoSgeSwitchDriver,
    "sge2000": CiscoSgeSwitchDriver,
    "aruba": ArubaSwitchDriver,
    "hp_procurve": ArubaSwitchDriver,
    "mikrotik": MikrotikSwitchDriver,
    "huawei": CiscoSwitchDriver,  # Similar CLI syntax
    "juniper": CiscoSwitchDriver,
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
        "id": "aruba",
        "name": "Aruba CX & HP ProCurve",
        "icon": "⚡",
        "description": "Aruba CX 6000/6200 and legacy HP ProCurve switches via SSH CLI",
        "default_port": 22,
        "requires_secret": False,
        "default_model": "Aruba 2930F Series",
    },
    {
        "id": "mikrotik",
        "name": "MikroTik Cloud Router Switch (SwOS/RouterOS)",
        "icon": "🔀",
        "description": "MikroTik CRS & Cloud Smart Switches using Bridge VLAN filtering",
        "default_port": 22,
        "requires_secret": False,
        "default_model": "MikroTik CRS326-24G",
    },
    {
        "id": "huawei",
        "name": "Huawei CloudEngine & Quidway",
        "icon": "🏮",
        "description": "Huawei VRP enterprise switches (S5700, S6700) using SSH VRP CLI",
        "default_port": 22,
        "requires_secret": False,
        "default_model": "Huawei S5720-28P",
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
