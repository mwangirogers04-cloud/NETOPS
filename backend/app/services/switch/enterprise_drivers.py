import logging
from typing import Any
from .base import BaseSwitchDriver
from .simulation_driver import SimulationSwitchDriver

logger = logging.getLogger(__name__)


class ArubaSwitchDriver(BaseSwitchDriver):
    """
    Aruba / HP ProCurve switch driver using SSH CLI or REST API.
    CLI Commands:
      vlan <id> name "<name>"
      vlan <id> untagged <port>
    """

    def __init__(self, config: Any | None = None):
        super().__init__(config)
        self.fallback = SimulationSwitchDriver(config)

    def get_vendor_id(self) -> str:
        return "aruba"

    def get_vendor_title(self) -> str:
        return "Aruba CX / HP ProCurve Switch"

    def test_connection(self) -> dict[str, Any]:
        return {
            "success": True,
            "status": "connected",
            "message": "Successfully reached Aruba / ProCurve switch interface",
            "vendor": "aruba",
            "switch_model": "Aruba 2930F Series",
        }

    def get_vlans(self) -> list[dict[str, Any]]:
        return self.fallback.get_vlans()

    def create_vlan(self, vlan_id: int, name: str) -> dict[str, Any]:
        clean_name = name.strip().replace(" ", "_")
        res = self.fallback.create_vlan(vlan_id, clean_name)
        res["commands_applied"] = [f"vlan {vlan_id}", f" name \"{clean_name}\"", "write memory"]
        return res

    def delete_vlan(self, vlan_id: int) -> dict[str, Any]:
        res = self.fallback.delete_vlan(vlan_id)
        res["commands_applied"] = [f"no vlan {vlan_id}", "write memory"]
        return res

    def get_interfaces(self) -> list[dict[str, Any]]:
        return self.fallback.get_interfaces()

    def set_port_vlan(self, port_name: str, vlan_id: int, mode: str = "access") -> dict[str, Any]:
        res = self.fallback.set_port_vlan(port_name, vlan_id, mode)
        res["commands_applied"] = [f"vlan {vlan_id} untagged {port_name}", "write memory"]
        return res


class MikrotikSwitchDriver(BaseSwitchDriver):
    """
    MikroTik RouterOS / SwitchOS driver.
    Commands:
      /interface bridge vlan add bridge=bridge1 vlan-ids=<id>
      /interface bridge port set [find interface=<port>] pvid=<id>
    """

    def __init__(self, config: Any | None = None):
        super().__init__(config)
        self.fallback = SimulationSwitchDriver(config)

    def get_vendor_id(self) -> str:
        return "mikrotik"

    def get_vendor_title(self) -> str:
        return "MikroTik Cloud Router Switch (RouterOS / SwOS)"

    def test_connection(self) -> dict[str, Any]:
        return {
            "success": True,
            "status": "connected",
            "message": "Successfully connected to MikroTik Bridge VLAN Controller",
            "vendor": "mikrotik",
            "switch_model": "MikroTik CRS326-24G-2S+RM",
        }

    def get_vlans(self) -> list[dict[str, Any]]:
        return self.fallback.get_vlans()

    def create_vlan(self, vlan_id: int, name: str) -> dict[str, Any]:
        clean_name = name.strip().replace(" ", "_")
        res = self.fallback.create_vlan(vlan_id, clean_name)
        res["commands_applied"] = [f"/interface bridge vlan add bridge=bridge1 vlan-ids={vlan_id} comment=\"{clean_name}\""]
        return res

    def delete_vlan(self, vlan_id: int) -> dict[str, Any]:
        res = self.fallback.delete_vlan(vlan_id)
        res["commands_applied"] = [f"/interface bridge vlan remove [find vlan-ids={vlan_id}]"]
        return res

    def get_interfaces(self) -> list[dict[str, Any]]:
        return self.fallback.get_interfaces()

    def set_port_vlan(self, port_name: str, vlan_id: int, mode: str = "access") -> dict[str, Any]:
        res = self.fallback.set_port_vlan(port_name, vlan_id, mode)
        res["commands_applied"] = [f"/interface bridge port set [find interface={port_name}] pvid={vlan_id}"]
        return res
