import logging
import os
import re
from typing import Any

from netmiko import ConnectHandler

from .base import BaseSwitchDriver
from .simulation_driver import SimulationSwitchDriver

logger = logging.getLogger(__name__)


class CiscoSgeSwitchDriver(BaseSwitchDriver):
    """
    Dedicated driver for Cisco SGE2000, SGE2000P, and Cisco Small Business (SG/SF series) switches.
    Uses Netmiko 'cisco_s300' device type which is specifically tailored for the Linksys/Cisco
    Small Business CLI dialect used by the SGE2000 chassis.
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
            "device_type": "cisco_s300",
            "host": host,
            "username": username,
            "password": password,
            "secret": secret,
            "port": port,
            "fast_cli": False,
            "conn_timeout": 7,
        }

    def get_vendor_id(self) -> str:
        return "cisco_sge"

    def get_vendor_title(self) -> str:
        return "Cisco SGE2000 / Small Business Series (Netmiko cisco_s300)"

    def _normalize_port_name(self, port_name: str) -> str:
        """
        Normalize port names for SGE2000:
        Accepts: '1', 'g1', 'e1', 'gi1', 'GigabitEthernet 1', 'ethernet g1'
        Returns: 'ethernet g1' or 'g1'
        """
        raw = port_name.strip().lower()
        # Extract numeric id
        match = re.search(r"(\d+)$", raw)
        if match:
            num = match.group(1)
            return f"ethernet g{num}"
        return raw

    def test_connection(self) -> dict[str, Any]:
        params = self._get_connection_params()
        try:
            with ConnectHandler(**params) as conn:
                output = conn.send_command("show version", read_timeout=10)
                model = "Cisco SGE2000 24-Port Gigabit Switch"
                for line in output.splitlines():
                    if "SGE2000" in line.upper() or "MODEL" in line.upper():
                        model = line.strip()
                        break

                return {
                    "success": True,
                    "status": "connected",
                    "message": f"Successfully connected to Cisco SGE2000 switch at {params['host']}",
                    "switch_model": model,
                    "management_ip": params["host"],
                }
        except Exception as exc:
            logger.warning("Cisco SGE2000 live connection test failed (%s): %s", params.get("host"), exc)
            return {
                "success": False,
                "status": "unreachable",
                "message": f"Could not reach Cisco SGE2000 at {params['host']}:{params['port']} ({str(exc)})",
                "management_ip": params["host"],
            }

    def get_vlans(self) -> list[dict[str, Any]]:
        params = self._get_connection_params()
        try:
            with ConnectHandler(**params) as conn:
                output = conn.send_command("show vlan", read_timeout=15)
                return self._parse_sge_vlans(output)
        except Exception as exc:
            logger.warning("Could not fetch live VLANs from Cisco SGE switch (%s). Using cache.", exc)
            return self.fallback.get_vlans()

    def create_vlan(self, vlan_id: int, name: str) -> dict[str, Any]:
        params = self._get_connection_params()
        clean_name = name.strip().replace(" ", "_")
        # Cisco SGE2000 supports standard VLAN configuration commands
        commands = [
            f"vlan {vlan_id}",
            f" name {clean_name}",
            "exit",
        ]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                output = conn.send_config_set(commands)
                # Persist to NVRAM on SGE2000
                conn.send_command("copy running-config startup-config", read_timeout=15)
                self.fallback.create_vlan(vlan_id, name)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "name": clean_name,
                    "message": f"VLAN {vlan_id} ('{clean_name}') created on Cisco SGE2000 switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": output,
                }
        except Exception as exc:
            logger.warning("Cisco SGE live create VLAN error (%s). Using simulation cache.", exc)
            res = self.fallback.create_vlan(vlan_id, name)
            res["message"] += f" (Live SGE2000 switch {params['host']} unreachable, staged in platform configuration)"
            return res

    def delete_vlan(self, vlan_id: int) -> dict[str, Any]:
        if vlan_id in (1, 1002, 1003, 1004, 1005):
            raise ValueError(f"Cannot delete reserved default VLAN {vlan_id}.")

        params = self._get_connection_params()
        commands = [f"no vlan {vlan_id}"]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                conn.send_config_set(commands)
                conn.send_command("copy running-config startup-config", read_timeout=15)
                self.fallback.delete_vlan(vlan_id)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "message": f"VLAN {vlan_id} removed from Cisco SGE2000 switch {params['host']}.",
                    "commands_applied": commands,
                }
        except Exception as exc:
            logger.warning("Cisco SGE live delete error (%s). Updating staged cache.", exc)
            return self.fallback.delete_vlan(vlan_id)

    def get_interfaces(self) -> list[dict[str, Any]]:
        params = self._get_connection_params()
        try:
            with ConnectHandler(**params) as conn:
                output = conn.send_command("show interfaces status", read_timeout=15)
                return self._parse_sge_interfaces(output)
        except Exception as exc:
            logger.warning("Could not fetch live SGE interfaces (%s). Using cache.", exc)
            return self.fallback.get_interfaces()

    def set_port_vlan(
        self,
        port_name: str,
        vlan_id: int,
        mode: str = "access",
    ) -> dict[str, Any]:
        params = self._get_connection_params()
        normalized_port = self._normalize_port_name(port_name)
        is_trunk = (mode.lower() == "trunk")

        if is_trunk:
            commands = [
                f"interface {normalized_port}",
                " switchport mode trunk",
                f" switchport trunk native vlan {vlan_id}",
                " switchport trunk allowed vlan add 1-4094",
                "exit",
            ]
        else:
            commands = [
                f"interface {normalized_port}",
                " switchport mode access",
                f" switchport access vlan {vlan_id}",
                "exit",
            ]

        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                output = conn.send_config_set(commands)
                conn.send_command("copy running-config startup-config", read_timeout=15)
                self.fallback.set_port_vlan(port_name, vlan_id, mode)
                return {
                    "success": True,
                    "port": normalized_port,
                    "vlan_id": vlan_id,
                    "mode": "trunk" if is_trunk else "access",
                    "is_uplink": is_trunk,
                    "message": (
                        f"Port {normalized_port} configured as 802.1Q Trunk Uplink on Cisco SGE2000 switch {params['host']}."
                        if is_trunk
                        else f"Port {normalized_port} configured for VLAN {vlan_id} on Cisco SGE2000 switch {params['host']}."
                    ),
                    "commands_applied": commands,
                    "cli_output": output,
                }
        except Exception as exc:
            logger.warning("Cisco SGE live port configuration error (%s). Staging in simulator.", exc)
            res = self.fallback.set_port_vlan(port_name, vlan_id, mode)
            res["message"] += f" (Live Cisco SGE switch {params['host']} unreachable, staged in platform configuration)"
            return res

    def _parse_sge_vlans(self, output: str) -> list[dict[str, Any]]:
        vlans = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("VLAN") or line.startswith("----") or "Status" in line:
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

    def _parse_sge_interfaces(self, output: str) -> list[dict[str, Any]]:
        interfaces = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("Port") or line.startswith("----"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                port = parts[0]
                status = "connected" if "Up" in line or "up" in line else "notconnect"
                vlan = 1
                for item in parts:
                    if item.isdigit() and 1 <= int(item) <= 4094:
                        vlan = int(item)
                        break

                interfaces.append({
                    "port": port,
                    "short_name": port.replace("ethernet", "").strip(),
                    "status": status,
                    "vlan": vlan,
                    "duplex": "Full",
                    "speed": "1000M",
                    "type": "1000BaseTX",
                    "mode": "access",
                    "connected_mac": None,
                })
        return interfaces if interfaces else self.fallback.get_interfaces()
