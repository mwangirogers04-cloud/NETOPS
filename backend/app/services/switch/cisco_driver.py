import logging
import os
import re
from typing import Any

from netmiko import ConnectHandler

from .base import BaseSwitchDriver, check_switch_reachability
from .simulation_driver import SimulationSwitchDriver

logger = logging.getLogger(__name__)


class CiscoSwitchDriver(BaseSwitchDriver):
    """
    Enterprise Cisco IOS / IOS-XE switch driver using SSH / Netmiko.
    Executes live configuration commands ('vlan <id>', 'switchport access vlan <id>', 'write memory')
    and parses live CLI outputs.
    """

    def __init__(self, config: Any | None = None):
        super().__init__(config)
        self.fallback = SimulationSwitchDriver(config)

    def _get_connection_params(self) -> dict[str, Any]:
        host = getattr(self.config, "management_ip", None) or os.getenv("NETOPS_SWITCH_MANAGEMENT_IP", "127.0.0.1")
        username = getattr(self.config, "username", None) or os.getenv("NETOPS_SWITCH_USERNAME", "admin")
        password = getattr(self.config, "password", None) or os.getenv("NETOPS_SWITCH_PASSWORD", "")
        secret = getattr(self.config, "enable_secret", None) or os.getenv("NETOPS_SWITCH_ENABLE_SECRET", "")
        port = getattr(self.config, "port", None) or 22

        return {
            "device_type": "cisco_ios",
            "host": host,
            "username": username,
            "password": password,
            "secret": secret,
            "port": port,
            "fast_cli": False,
            "conn_timeout": 5,
        }

    def get_vendor_id(self) -> str:
        return "cisco_ios"

    def get_vendor_title(self) -> str:
        return "Cisco Catalyst / IOS-XE Switch (SSH Netmiko)"

    def test_connection(self) -> dict[str, Any]:
        params = self._get_connection_params()
        if not check_switch_reachability(params["host"], params["port"], timeout=0.8):
            return {
                "success": False,
                "status": "unreachable",
                "message": f"Could not reach switch at {params['host']}:{params['port']} (Connection timed out). Using safe simulation fallback.",
                "management_ip": params["host"],
                "switch_model": "Cisco Switch (Simulation Mode)",
            }
        try:
            with ConnectHandler(**params) as conn:
                output = conn.send_command("show version", read_timeout=10)
                model = "Cisco Switch"
                match = re.search(r"[Cc]isco\s+([A-Za-z0-9\-]+)\s+.*processor", output)
                if match:
                    model = f"Cisco {match.group(1)}"

                return {
                    "success": True,
                    "status": "connected",
                    "message": f"Successfully connected to {params['host']} via SSH",
                    "switch_model": model,
                    "management_ip": params["host"],
                }
        except Exception as exc:
            logger.warning("Cisco live connection test failed (%s): %s", params.get("host"), exc)
            # If testing or offline lab, report status and allow fallback
            return {
                "success": False,
                "status": "unreachable",
                "message": f"Could not reach switch at {params['host']}:{params['port']} ({str(exc)})",
                "management_ip": params["host"],
            }

    def get_vlans(self) -> list[dict[str, Any]]:
        params = self._get_connection_params()
        if not check_switch_reachability(params["host"], params["port"]):
            return self.fallback.get_vlans()
        try:
            with ConnectHandler(**params) as conn:
                output = conn.send_command("show vlan brief", read_timeout=15)
                return self._parse_vlan_brief(output)
        except Exception as exc:
            logger.warning("Could not fetch live VLANs from Cisco switch (%s). Using cache.", exc)
            return self.fallback.get_vlans()

    def create_vlan(self, vlan_id: int, name: str) -> dict[str, Any]:
        params = self._get_connection_params()
        clean_name = name.strip().replace(" ", "_")
        commands = [
            f"vlan {vlan_id}",
            f" name {clean_name}",
            "end",
            "write memory",
        ]
        if not check_switch_reachability(params["host"], params["port"]):
            res = self.fallback.create_vlan(vlan_id, name)
            res["message"] += f" (Live switch {params['host']} unreachable, staged in platform configuration)"
            return res
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                output = conn.send_config_set(commands[:2])
                conn.send_command("write memory", read_timeout=15)
                # Keep fallback in sync
                self.fallback.create_vlan(vlan_id, name)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "name": clean_name,
                    "message": f"VLAN {vlan_id} ('{clean_name}') successfully pushed to Cisco switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": output,
                }
        except Exception as exc:
            logger.warning("Cisco live command error (%s). Falling back to simulation.", exc)
            res = self.fallback.create_vlan(vlan_id, name)
            res["message"] += f" (Live switch {params['host']} unreachable, staged in platform configuration)"
            return res

    def delete_vlan(self, vlan_id: int) -> dict[str, Any]:
        if vlan_id in (1, 1002, 1003, 1004, 1005):
            raise ValueError(f"Cannot delete reserved default VLAN {vlan_id}.")

        params = self._get_connection_params()
        if not check_switch_reachability(params["host"], params["port"]):
            return self.fallback.delete_vlan(vlan_id)
        commands = [
            f"no vlan {vlan_id}",
            "end",
            "write memory",
        ]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                conn.send_config_set([f"no vlan {vlan_id}"])
                conn.send_command("write memory", read_timeout=15)
                self.fallback.delete_vlan(vlan_id)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "message": f"VLAN {vlan_id} removed from Cisco switch {params['host']}.",
                    "commands_applied": commands,
                }
        except Exception as exc:
            logger.warning("Cisco live delete error (%s). Updating staged cache.", exc)
            return self.fallback.delete_vlan(vlan_id)

    def get_interfaces(self) -> list[dict[str, Any]]:
        params = self._get_connection_params()
        if not check_switch_reachability(params["host"], params["port"]):
            return self.fallback.get_interfaces()
        try:
            with ConnectHandler(**params) as conn:
                output = conn.send_command("show interfaces status", read_timeout=15)
                return self._parse_interfaces_status(output)
        except Exception as exc:
            logger.warning("Could not fetch live interfaces from Cisco switch (%s). Using cache.", exc)
            return self.fallback.get_interfaces()

    def set_port_vlan(
        self,
        port_name: str,
        vlan_id: int,
        mode: str = "access",
    ) -> dict[str, Any]:
        params = self._get_connection_params()
        clean_port = port_name.strip()
        is_trunk = (mode.lower() == "trunk")

        if not check_switch_reachability(params["host"], params["port"]):
            res = self.fallback.set_port_vlan(clean_port, vlan_id, mode)
            res["message"] += f" (Live switch {params['host']} unreachable, staged in platform configuration)"
            return res

        if is_trunk:
            commands = [
                f"interface {clean_port}",
                " switchport trunk encapsulation dot1q",
                " switchport mode trunk",
                f" switchport trunk native vlan {vlan_id}",
                " switchport trunk allowed vlan all",
                "end",
                "write memory",
            ]
        else:
            commands = [
                f"interface {clean_port}",
                " switchport mode access",
                f" switchport access vlan {vlan_id}",
                "end",
                "write memory",
            ]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                output = conn.send_config_set(commands[:-2])
                conn.send_command("write memory", read_timeout=15)
                self.fallback.set_port_vlan(clean_port, vlan_id, mode)
                return {
                    "success": True,
                    "port": clean_port,
                    "vlan_id": vlan_id,
                    "mode": "trunk" if is_trunk else "access",
                    "is_uplink": is_trunk,
                    "message": (
                        f"Port {clean_port} configured as 802.1Q Trunk Uplink on Cisco switch {params['host']}."
                        if is_trunk
                        else f"Port {clean_port} configured for VLAN {vlan_id} on Cisco switch {params['host']}."
                    ),
                    "commands_applied": commands,
                    "cli_output": output,
                }
        except Exception as exc:
            logger.warning("Cisco live port configuration error (%s). Staging in simulator.", exc)
            res = self.fallback.set_port_vlan(clean_port, vlan_id, mode)
            res["message"] += f" (Live switch {params['host']} unreachable, staged in platform configuration)"
            return res

    def _parse_vlan_brief(self, output: str) -> list[dict[str, Any]]:
        vlans = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("VLAN") or line.startswith("----"):
                continue
            parts = line.split()
            if parts and parts[0].isdigit():
                vlan_id = int(parts[0])
                name = parts[1] if len(parts) > 1 else f"VLAN_{vlan_id}"
                status = parts[2] if len(parts) > 2 else "active"
                ports = " ".join(parts[3:]) if len(parts) > 3 else ""
                vlans.append({
                    "vlan_id": vlan_id,
                    "name": name,
                    "status": status,
                    "ports": ports,
                })
        return vlans if vlans else self.fallback.get_vlans()

    def _parse_interfaces_status(self, output: str) -> list[dict[str, Any]]:
        interfaces = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("Port") or line.startswith("----"):
                continue
            parts = line.split()
            if len(parts) >= 6:
                port = parts[0]
                status = parts[1] if parts[1] in ("connected", "notconnect", "disabled") else parts[2]
                vlan = int(parts[2]) if parts[2].isdigit() else (int(parts[3]) if parts[3].isdigit() else 1)
                interfaces.append({
                    "port": port,
                    "short_name": port,
                    "status": status,
                    "vlan": vlan,
                    "duplex": "auto",
                    "speed": "auto",
                    "type": "10/100/1000BaseTX",
                    "mode": "access",
                    "connected_mac": None,
                })
        return interfaces if interfaces else self.fallback.get_interfaces()

    def get_running_config(self) -> str:
        """
        Pull live running configuration from the Cisco switch via Netmiko.
        Falls back to realistic simulated config if device is offline/unreachable.
        """
        params = self._get_connection_params()
        if not check_switch_reachability(params["host"], params["port"]):
            return self.fallback.get_running_config()
        try:
            with ConnectHandler(**params) as conn:
                if params.get("secret"):
                    conn.enable()
                output = conn.send_command("show running-config", read_timeout=30)
                if output and "hostname" in output.lower():
                    return output
        except Exception as exc:
            logger.warning("Cisco show running-config failed (%s): %s; falling back to simulation.", params.get("host"), exc)

        return self.fallback.get_running_config()
