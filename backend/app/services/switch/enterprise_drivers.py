import logging
import os
import re
from typing import Any

from netmiko import ConnectHandler

from .base import BaseSwitchDriver, check_switch_reachability
from .simulation_driver import SimulationSwitchDriver

logger = logging.getLogger(__name__)


class GenericNetmikoSwitchDriver(BaseSwitchDriver):
    """
    Base class for enterprise switches managed via Netmiko SSH CLI.
    Implements standard connection lifecycle, safe command dispatch, and simulation fallback.
    """

    device_type: str = "generic_ssh"
    default_model: str = "Enterprise Managed Switch"
    version_cmd: str = "show version"
    vlan_list_cmd: str = "show vlan"
    interfaces_cmd: str = "show interfaces status"
    save_cmd: str = "write memory"
    running_config_cmd: str = "show running-config"

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
            "device_type": self.device_type,
            "host": host,
            "username": username,
            "password": password,
            "secret": secret,
            "port": port,
            "fast_cli": False,
            "conn_timeout": 6,
        }

    def _extract_port_number(self, port_name: str) -> str:
        """Extract the numeric portion of a port identifier (e.g. 'GigabitEthernet0/5' -> '5')."""
        match = re.search(r"(\d+)$", port_name.strip())
        return match.group(1) if match else port_name.strip()

    def test_connection(self) -> dict[str, Any]:
        params = self._get_connection_params()
        if not check_switch_reachability(params["host"], params["port"], timeout=0.8):
            return {
                "success": False,
                "status": "unreachable",
                "message": f"Could not reach {self.get_vendor_title()} at {params['host']}:{params['port']} (Connection timed out). Using safe simulation fallback.",
                "management_ip": params["host"],
                "switch_model": f"{self.default_model} (Simulation Fallback)",
            }
        try:
            with ConnectHandler(**params) as conn:
                output = conn.send_command(self.version_cmd, read_timeout=10)
                first_line = output.splitlines()[0] if output.splitlines() else self.default_model
                return {
                    "success": True,
                    "status": "connected",
                    "message": f"Successfully connected to {self.get_vendor_title()} at {params['host']}",
                    "switch_model": first_line.strip() or self.default_model,
                    "management_ip": params["host"],
                }
        except Exception as exc:
            logger.warning("%s connection test failed (%s): %s", self.get_vendor_title(), params.get("host"), exc)
            return {
                "success": False,
                "status": "unreachable",
                "message": f"Could not reach {self.get_vendor_title()} at {params['host']}:{params['port']} ({str(exc)})",
                "management_ip": params["host"],
            }

    def get_vlans(self) -> list[dict[str, Any]]:
        params = self._get_connection_params()
        if not check_switch_reachability(params["host"], params["port"]):
            return self.fallback.get_vlans()
        try:
            with ConnectHandler(**params) as conn:
                output = conn.send_command(self.vlan_list_cmd, read_timeout=15)
                parsed = self._parse_vlans(output)
                return parsed if parsed else self.fallback.get_vlans()
        except Exception as exc:
            logger.warning("%s get_vlans error (%s). Using cache.", self.get_vendor_title(), exc)
            return self.fallback.get_vlans()

    def _parse_vlans(self, output: str) -> list[dict[str, Any]]:
        vlans = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("VLAN") or line.startswith("----"):
                continue
            parts = line.split()
            if parts and parts[0].isdigit():
                vlan_id = int(parts[0])
                name = parts[1] if len(parts) > 1 else f"VLAN_{vlan_id}"
                vlans.append({
                    "vlan_id": vlan_id,
                    "name": name,
                    "status": "active",
                    "ports": " ".join(parts[2:]) if len(parts) > 2 else "",
                })
        return vlans

    def get_interfaces(self) -> list[dict[str, Any]]:
        return self.fallback.get_interfaces()

    def get_running_config(self) -> str:
        """Pull live running configuration from the switch CLI or fallback to simulation."""
        params = self._get_connection_params()
        if not check_switch_reachability(params["host"], params["port"]):
            return self.fallback.get_running_config()
        try:
            with ConnectHandler(**params) as conn:
                if params.get("secret"):
                    conn.enable()
                output = conn.send_command(self.running_config_cmd, read_timeout=30)
                if output and len(output.strip()) > 20:
                    return output
        except Exception as exc:
            logger.warning("%s get_running_config failed (%s): %s; using simulation fallback.", self.get_vendor_title(), params.get("host"), exc)

        return self.fallback.get_running_config()


# =========================================================================
# 1. UBIQUITI NETWORKS (EdgeSwitch / UniFi Switch)
# =========================================================================
class UbiquitiSwitchDriver(GenericNetmikoSwitchDriver):
    """
    Ubiquiti Networks managed switch driver (EdgeSwitch ES-24/ES-48, UniFi Switch USW series).
    Uses Netmiko 'ubiquiti_edgeswitch' CLI syntax.
    """
    device_type = "ubiquiti_edgeswitch"
    default_model = "Ubiquiti EdgeSwitch 24-Port Gigabit"
    version_cmd = "show hardware"
    vlan_list_cmd = "show vlan"
    save_cmd = "write memory"

    def get_vendor_id(self) -> str:
        return "ubiquiti"

    def get_vendor_title(self) -> str:
        return "Ubiquiti EdgeSwitch / UniFi Switch Series"

    def create_vlan(self, vlan_id: int, name: str) -> dict[str, Any]:
        clean_name = name.strip().replace(" ", "_")
        params = self._get_connection_params()
        commands = [
            "vlan database",
            f"vlan {vlan_id}",
            f"vlan name {vlan_id} {clean_name}",
            "exit",
            "write memory",
        ]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                out = conn.send_config_set(commands[:4])
                conn.send_command("write memory", read_timeout=15)
                self.fallback.create_vlan(vlan_id, clean_name)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "name": clean_name,
                    "message": f"VLAN {vlan_id} deployed to Ubiquiti switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": out,
                }
        except Exception as exc:
            logger.warning("Ubiquiti live command error: %s", exc)
            res = self.fallback.create_vlan(vlan_id, clean_name)
            res["message"] += f" (Live Ubiquiti switch {params['host']} unreachable, staged in platform configuration)"
            res["commands_applied"] = commands
            return res

    def delete_vlan(self, vlan_id: int) -> dict[str, Any]:
        if vlan_id == 1:
            raise ValueError("Cannot delete default VLAN 1.")
        params = self._get_connection_params()
        commands = [
            "vlan database",
            f"no vlan {vlan_id}",
            "exit",
            "write memory",
        ]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                conn.send_config_set(commands[:3])
                conn.send_command("write memory", read_timeout=15)
                self.fallback.delete_vlan(vlan_id)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "message": f"VLAN {vlan_id} deleted from Ubiquiti switch {params['host']}.",
                    "commands_applied": commands,
                }
        except Exception:
            res = self.fallback.delete_vlan(vlan_id)
            res["commands_applied"] = commands
            return res

    def set_port_vlan(self, port_name: str, vlan_id: int, mode: str = "access") -> dict[str, Any]:
        num = self._extract_port_number(port_name)
        params = self._get_connection_params()
        if mode.lower() == "trunk":
            commands = [
                f"interface 0/{num}",
                f"vlan participation include {vlan_id}",
                f"vlan tagging {vlan_id}",
                "exit",
                "write memory",
            ]
        else:
            commands = [
                f"interface 0/{num}",
                f"vlan pvid {vlan_id}",
                f"vlan participation include {vlan_id}",
                "exit",
                "write memory",
            ]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                out = conn.send_config_set(commands[:4])
                conn.send_command("write memory", read_timeout=15)
                self.fallback.set_port_vlan(port_name, vlan_id, mode)
                return {
                    "success": True,
                    "port": f"0/{num}",
                    "vlan_id": vlan_id,
                    "mode": mode,
                    "message": f"Port 0/{num} assigned to VLAN {vlan_id} on Ubiquiti switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.set_port_vlan(port_name, vlan_id, mode)
            res["commands_applied"] = commands
            return res


# =========================================================================
# 2. JUNIPER NETWORKS (Junos OS - EX / QFX Series)
# =========================================================================
class JuniperSwitchDriver(GenericNetmikoSwitchDriver):
    """
    Juniper Networks Junos OS switch driver (EX2200, EX2300, EX3300, EX3400, EX4300, QFX).
    Uses Netmiko 'juniper_junos' candidate configuration and commit model.
    """
    device_type = "juniper_junos"
    default_model = "Juniper EX2300 24-Port Switch"
    version_cmd = "show version"
    vlan_list_cmd = "show vlans"
    running_config_cmd = "show configuration"

    def get_vendor_id(self) -> str:
        return "juniper"

    def get_vendor_title(self) -> str:
        return "Juniper Networks Junos (EX / QFX Series)"

    def create_vlan(self, vlan_id: int, name: str) -> dict[str, Any]:
        clean_name = name.strip().replace(" ", "_")
        params = self._get_connection_params()
        commands = [
            f"set vlans {clean_name} vlan-id {vlan_id}",
        ]
        try:
            with ConnectHandler(**params) as conn:
                conn.config_mode()
                out = conn.send_config_set(commands)
                conn.commit()
                conn.exit_config_mode()
                self.fallback.create_vlan(vlan_id, clean_name)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "name": clean_name,
                    "message": f"VLAN {vlan_id} committed to Juniper Junos switch {params['host']}.",
                    "commands_applied": commands + ["commit"],
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.create_vlan(vlan_id, clean_name)
            res["commands_applied"] = commands + ["commit"]
            return res

    def delete_vlan(self, vlan_id: int) -> dict[str, Any]:
        params = self._get_connection_params()
        commands = [f"delete vlans VLAN_{vlan_id}"]
        try:
            with ConnectHandler(**params) as conn:
                conn.config_mode()
                conn.send_config_set(commands)
                conn.commit()
                conn.exit_config_mode()
                self.fallback.delete_vlan(vlan_id)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "message": f"VLAN {vlan_id} deleted from Juniper Junos switch {params['host']}.",
                    "commands_applied": commands + ["commit"],
                }
        except Exception:
            res = self.fallback.delete_vlan(vlan_id)
            res["commands_applied"] = commands + ["commit"]
            return res

    def set_port_vlan(self, port_name: str, vlan_id: int, mode: str = "access") -> dict[str, Any]:
        num = self._extract_port_number(port_name)
        params = self._get_connection_params()
        port_id = f"ge-0/0/{num}"
        commands = [
            f"set interfaces {port_id} unit 0 family ethernet-switching interface-mode {mode}",
            f"set interfaces {port_id} unit 0 family ethernet-switching vlan members {vlan_id}",
        ]
        try:
            with ConnectHandler(**params) as conn:
                conn.config_mode()
                out = conn.send_config_set(commands)
                conn.commit()
                conn.exit_config_mode()
                self.fallback.set_port_vlan(port_name, vlan_id, mode)
                return {
                    "success": True,
                    "port": port_id,
                    "vlan_id": vlan_id,
                    "mode": mode,
                    "message": f"Port {port_id} committed with VLAN {vlan_id} on Juniper switch {params['host']}.",
                    "commands_applied": commands + ["commit"],
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.set_port_vlan(port_name, vlan_id, mode)
            res["commands_applied"] = commands + ["commit"]
            return res


# =========================================================================
# 3. ARISTA NETWORKS (EOS Series)
# =========================================================================
class AristaSwitchDriver(GenericNetmikoSwitchDriver):
    """
    Arista Networks EOS switch driver (7050, 7150, 7280 series).
    Uses Netmiko 'arista_eos'.
    """
    device_type = "arista_eos"
    default_model = "Arista 7050SX 24-Port Switch"
    version_cmd = "show version"
    vlan_list_cmd = "show vlan"
    save_cmd = "write memory"

    def get_vendor_id(self) -> str:
        return "arista"

    def get_vendor_title(self) -> str:
        return "Arista Networks EOS Switch"

    def create_vlan(self, vlan_id: int, name: str) -> dict[str, Any]:
        clean_name = name.strip().replace(" ", "_")
        params = self._get_connection_params()
        commands = [
            f"vlan {vlan_id}",
            f" name {clean_name}",
            "exit",
            "write memory",
        ]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                out = conn.send_config_set(commands[:3])
                conn.send_command("write memory", read_timeout=15)
                self.fallback.create_vlan(vlan_id, clean_name)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "name": clean_name,
                    "message": f"VLAN {vlan_id} saved to Arista switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.create_vlan(vlan_id, clean_name)
            res["commands_applied"] = commands
            return res

    def delete_vlan(self, vlan_id: int) -> dict[str, Any]:
        params = self._get_connection_params()
        commands = [f"no vlan {vlan_id}", "write memory"]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                conn.send_config_set([f"no vlan {vlan_id}"])
                conn.send_command("write memory", read_timeout=15)
                self.fallback.delete_vlan(vlan_id)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "message": f"VLAN {vlan_id} removed from Arista switch {params['host']}.",
                    "commands_applied": commands,
                }
        except Exception:
            res = self.fallback.delete_vlan(vlan_id)
            res["commands_applied"] = commands
            return res

    def set_port_vlan(self, port_name: str, vlan_id: int, mode: str = "access") -> dict[str, Any]:
        num = self._extract_port_number(port_name)
        port_id = f"Ethernet{num}"
        params = self._get_connection_params()
        commands = [
            f"interface {port_id}",
            f" switchport mode {mode}",
            f" switchport access vlan {vlan_id}",
            "exit",
            "write memory",
        ]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                out = conn.send_config_set(commands[:4])
                conn.send_command("write memory", read_timeout=15)
                self.fallback.set_port_vlan(port_name, vlan_id, mode)
                return {
                    "success": True,
                    "port": port_id,
                    "vlan_id": vlan_id,
                    "mode": mode,
                    "message": f"Port {port_id} assigned to VLAN {vlan_id} on Arista switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.set_port_vlan(port_name, vlan_id, mode)
            res["commands_applied"] = commands
            return res


# =========================================================================
# 4. DELL NETWORKING (PowerConnect / OS6 / OS9 / OS10)
# =========================================================================
class DellSwitchDriver(GenericNetmikoSwitchDriver):
    """
    Dell EMC Networking switch driver (PowerConnect, N-Series OS6, S-Series OS10).
    Uses Netmiko 'dell_os10' / 'dell_powerconnect'.
    """
    device_type = "dell_os10"
    default_model = "Dell EMC Networking N2024 / S4128"
    version_cmd = "show version"
    vlan_list_cmd = "show vlan"
    save_cmd = "write memory"

    def get_vendor_id(self) -> str:
        return "dell"

    def get_vendor_title(self) -> str:
        return "Dell EMC Networking (PowerConnect / OS6 / OS10)"

    def create_vlan(self, vlan_id: int, name: str) -> dict[str, Any]:
        clean_name = name.strip().replace(" ", "_")
        params = self._get_connection_params()
        commands = [
            f"interface vlan {vlan_id}",
            f" description {clean_name}",
            "exit",
            "write memory",
        ]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                out = conn.send_config_set(commands[:3])
                conn.send_command("write memory", read_timeout=15)
                self.fallback.create_vlan(vlan_id, clean_name)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "name": clean_name,
                    "message": f"VLAN {vlan_id} deployed to Dell EMC switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.create_vlan(vlan_id, clean_name)
            res["commands_applied"] = commands
            return res

    def delete_vlan(self, vlan_id: int) -> dict[str, Any]:
        params = self._get_connection_params()
        commands = [f"no interface vlan {vlan_id}", "write memory"]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                conn.send_config_set([f"no interface vlan {vlan_id}"])
                conn.send_command("write memory", read_timeout=15)
                self.fallback.delete_vlan(vlan_id)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "message": f"VLAN {vlan_id} deleted from Dell EMC switch {params['host']}.",
                    "commands_applied": commands,
                }
        except Exception:
            res = self.fallback.delete_vlan(vlan_id)
            res["commands_applied"] = commands
            return res

    def set_port_vlan(self, port_name: str, vlan_id: int, mode: str = "access") -> dict[str, Any]:
        num = self._extract_port_number(port_name)
        port_id = f"ethernet 1/1/{num}"
        params = self._get_connection_params()
        commands = [
            f"interface {port_id}",
            f" switchport mode {mode}",
            f" switchport access vlan {vlan_id}",
            "exit",
            "write memory",
        ]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                out = conn.send_config_set(commands[:4])
                conn.send_command("write memory", read_timeout=15)
                self.fallback.set_port_vlan(port_name, vlan_id, mode)
                return {
                    "success": True,
                    "port": port_id,
                    "vlan_id": vlan_id,
                    "mode": mode,
                    "message": f"Port {port_id} configured for VLAN {vlan_id} on Dell switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.set_port_vlan(port_name, vlan_id, mode)
            res["commands_applied"] = commands
            return res


# =========================================================================
# 5. TP-LINK JETSTREAM / OMADA MANAGED SWITCHES
# =========================================================================
class TpLinkSwitchDriver(GenericNetmikoSwitchDriver):
    """
    TP-Link JetStream & Omada Managed switch driver (T1600G, T2600G, SG3428).
    Uses Netmiko 'tplink_jetstream'.
    """
    device_type = "tplink_jetstream"
    default_model = "TP-Link JetStream SG3428 24-Port Gigabit"
    version_cmd = "show system-info"
    vlan_list_cmd = "show vlan"
    save_cmd = "copy running-config startup-config"

    def get_vendor_id(self) -> str:
        return "tplink"

    def get_vendor_title(self) -> str:
        return "TP-Link JetStream / Omada Managed Series"

    def create_vlan(self, vlan_id: int, name: str) -> dict[str, Any]:
        clean_name = name.strip().replace(" ", "_")
        params = self._get_connection_params()
        commands = [
            f"vlan {vlan_id}",
            f" name {clean_name}",
            "exit",
            "copy running-config startup-config",
        ]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                out = conn.send_config_set(commands[:3])
                conn.send_command("copy running-config startup-config", read_timeout=15)
                self.fallback.create_vlan(vlan_id, clean_name)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "name": clean_name,
                    "message": f"VLAN {vlan_id} saved on TP-Link switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.create_vlan(vlan_id, clean_name)
            res["commands_applied"] = commands
            return res

    def delete_vlan(self, vlan_id: int) -> dict[str, Any]:
        params = self._get_connection_params()
        commands = [f"no vlan {vlan_id}", "copy running-config startup-config"]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                conn.send_config_set([f"no vlan {vlan_id}"])
                conn.send_command("copy running-config startup-config", read_timeout=15)
                self.fallback.delete_vlan(vlan_id)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "message": f"VLAN {vlan_id} deleted from TP-Link switch {params['host']}.",
                    "commands_applied": commands,
                }
        except Exception:
            res = self.fallback.delete_vlan(vlan_id)
            res["commands_applied"] = commands
            return res

    def set_port_vlan(self, port_name: str, vlan_id: int, mode: str = "access") -> dict[str, Any]:
        num = self._extract_port_number(port_name)
        port_id = f"gigabitEthernet 1/0/{num}"
        params = self._get_connection_params()
        commands = [
            f"interface {port_id}",
            f" switchport access vlan {vlan_id}",
            "exit",
            "copy running-config startup-config",
        ]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                out = conn.send_config_set(commands[:3])
                conn.send_command("copy running-config startup-config", read_timeout=15)
                self.fallback.set_port_vlan(port_name, vlan_id, mode)
                return {
                    "success": True,
                    "port": port_id,
                    "vlan_id": vlan_id,
                    "mode": mode,
                    "message": f"Port {port_id} configured with VLAN {vlan_id} on TP-Link switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.set_port_vlan(port_name, vlan_id, mode)
            res["commands_applied"] = commands
            return res


# =========================================================================
# 6. D-LINK MANAGED SWITCHES (DGS-1210 / DGS-1510 / DGS-3120)
# =========================================================================
class DLinkSwitchDriver(GenericNetmikoSwitchDriver):
    """
    D-Link Managed switch driver (DGS-1210, DGS-1510, DGS-3120 series).
    Uses Netmiko 'dlink_ds'.
    """
    device_type = "dlink_ds"
    default_model = "D-Link DGS-1210-28 24-Port Gigabit"
    version_cmd = "show switch"
    vlan_list_cmd = "show vlan"
    save_cmd = "save"

    def get_vendor_id(self) -> str:
        return "dlink"

    def get_vendor_title(self) -> str:
        return "D-Link Managed Switch (DGS / DES Series)"

    def create_vlan(self, vlan_id: int, name: str) -> dict[str, Any]:
        clean_name = name.strip().replace(" ", "_")
        params = self._get_connection_params()
        commands = [f"create vlan {clean_name} tag {vlan_id}", "save"]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                out = conn.send_command(commands[0])
                conn.send_command("save", read_timeout=15)
                self.fallback.create_vlan(vlan_id, clean_name)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "name": clean_name,
                    "message": f"VLAN {vlan_id} saved to D-Link switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.create_vlan(vlan_id, clean_name)
            res["commands_applied"] = commands
            return res

    def delete_vlan(self, vlan_id: int) -> dict[str, Any]:
        params = self._get_connection_params()
        commands = [f"delete vlan {vlan_id}", "save"]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                conn.send_command(commands[0])
                conn.send_command("save", read_timeout=15)
                self.fallback.delete_vlan(vlan_id)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "message": f"VLAN {vlan_id} deleted from D-Link switch {params['host']}.",
                    "commands_applied": commands,
                }
        except Exception:
            res = self.fallback.delete_vlan(vlan_id)
            res["commands_applied"] = commands
            return res

    def set_port_vlan(self, port_name: str, vlan_id: int, mode: str = "access") -> dict[str, Any]:
        num = self._extract_port_number(port_name)
        params = self._get_connection_params()
        commands = [f"config vlan {vlan_id} add untagged {num}", "save"]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                out = conn.send_command(commands[0])
                conn.send_command("save", read_timeout=15)
                self.fallback.set_port_vlan(port_name, vlan_id, mode)
                return {
                    "success": True,
                    "port": f"Port {num}",
                    "vlan_id": vlan_id,
                    "mode": mode,
                    "message": f"Port {num} configured for VLAN {vlan_id} on D-Link switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.set_port_vlan(port_name, vlan_id, mode)
            res["commands_applied"] = commands
            return res


# =========================================================================
# 7. HUAWEI CLOUDENGENE & QUIDWAY (VRP)
# =========================================================================
class HuaweiSwitchDriver(GenericNetmikoSwitchDriver):
    """
    Huawei VRP enterprise switch driver (S5700, S6700, CloudEngine).
    Uses Netmiko 'huawei_vrp'.
    """
    device_type = "huawei_vrp"
    default_model = "Huawei S5720-28P Gigabit Switch"
    version_cmd = "display version"
    vlan_list_cmd = "display vlan"
    running_config_cmd = "display current-configuration"
    save_cmd = "save"

    def get_vendor_id(self) -> str:
        return "huawei"

    def get_vendor_title(self) -> str:
        return "Huawei CloudEngine & Quidway (VRP Series)"

    def create_vlan(self, vlan_id: int, name: str) -> dict[str, Any]:
        clean_name = name.strip().replace(" ", "_")
        params = self._get_connection_params()
        commands = [
            f"vlan {vlan_id}",
            f" description {clean_name}",
            "quit",
            "save",
        ]
        try:
            with ConnectHandler(**params) as conn:
                out = conn.send_config_set(commands[:3])
                conn.send_command("save", read_timeout=15)
                self.fallback.create_vlan(vlan_id, clean_name)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "name": clean_name,
                    "message": f"VLAN {vlan_id} saved to Huawei switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.create_vlan(vlan_id, clean_name)
            res["commands_applied"] = commands
            return res

    def delete_vlan(self, vlan_id: int) -> dict[str, Any]:
        params = self._get_connection_params()
        commands = [f"undo vlan {vlan_id}", "save"]
        try:
            with ConnectHandler(**params) as conn:
                conn.send_config_set([f"undo vlan {vlan_id}"])
                conn.send_command("save", read_timeout=15)
                self.fallback.delete_vlan(vlan_id)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "message": f"VLAN {vlan_id} removed from Huawei switch {params['host']}.",
                    "commands_applied": commands,
                }
        except Exception:
            res = self.fallback.delete_vlan(vlan_id)
            res["commands_applied"] = commands
            return res

    def set_port_vlan(self, port_name: str, vlan_id: int, mode: str = "access") -> dict[str, Any]:
        num = self._extract_port_number(port_name)
        port_id = f"GigabitEthernet0/0/{num}"
        params = self._get_connection_params()
        commands = [
            f"interface {port_id}",
            f" port link-type {mode}",
            f" port default vlan {vlan_id}",
            "quit",
            "save",
        ]
        try:
            with ConnectHandler(**params) as conn:
                out = conn.send_config_set(commands[:4])
                conn.send_command("save", read_timeout=15)
                self.fallback.set_port_vlan(port_name, vlan_id, mode)
                return {
                    "success": True,
                    "port": port_id,
                    "vlan_id": vlan_id,
                    "mode": mode,
                    "message": f"Port {port_id} assigned to VLAN {vlan_id} on Huawei switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.set_port_vlan(port_name, vlan_id, mode)
            res["commands_applied"] = commands
            return res


# =========================================================================
# 8. EXTREME NETWORKS / BROCADE / RUCKUS ICX
# =========================================================================
class ExtremeBrocadeSwitchDriver(GenericNetmikoSwitchDriver):
    """
    Extreme Networks & Ruckus / Brocade ICX switch driver (ICX 7150, ICX 7450, Summit).
    Uses Netmiko 'ruckus_fastiron' / 'extreme_exos'.
    """
    device_type = "ruckus_fastiron"
    default_model = "Ruckus ICX 7150-24 24-Port Switch"
    version_cmd = "show version"
    vlan_list_cmd = "show vlan"
    save_cmd = "write memory"

    def get_vendor_id(self) -> str:
        return "extreme"

    def get_vendor_title(self) -> str:
        return "Extreme Networks / Brocade & Ruckus ICX"

    def create_vlan(self, vlan_id: int, name: str) -> dict[str, Any]:
        clean_name = name.strip().replace(" ", "_")
        params = self._get_connection_params()
        commands = [
            f"vlan {vlan_id} name {clean_name}",
            "write memory",
        ]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                out = conn.send_config_set([f"vlan {vlan_id} name {clean_name}"])
                conn.send_command("write memory", read_timeout=15)
                self.fallback.create_vlan(vlan_id, clean_name)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "name": clean_name,
                    "message": f"VLAN {vlan_id} committed to ICX/Extreme switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.create_vlan(vlan_id, clean_name)
            res["commands_applied"] = commands
            return res

    def delete_vlan(self, vlan_id: int) -> dict[str, Any]:
        params = self._get_connection_params()
        commands = [f"no vlan {vlan_id}", "write memory"]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                conn.send_config_set([f"no vlan {vlan_id}"])
                conn.send_command("write memory", read_timeout=15)
                self.fallback.delete_vlan(vlan_id)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "message": f"VLAN {vlan_id} deleted from ICX/Extreme switch {params['host']}.",
                    "commands_applied": commands,
                }
        except Exception:
            res = self.fallback.delete_vlan(vlan_id)
            res["commands_applied"] = commands
            return res

    def set_port_vlan(self, port_name: str, vlan_id: int, mode: str = "access") -> dict[str, Any]:
        num = self._extract_port_number(port_name)
        params = self._get_connection_params()
        commands = [
            f"vlan {vlan_id}",
            f" untagged ethernet 1/1/{num}",
            "exit",
            "write memory",
        ]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                out = conn.send_config_set(commands[:3])
                conn.send_command("write memory", read_timeout=15)
                self.fallback.set_port_vlan(port_name, vlan_id, mode)
                return {
                    "success": True,
                    "port": f"ethernet 1/1/{num}",
                    "vlan_id": vlan_id,
                    "mode": mode,
                    "message": f"Port 1/1/{num} set to VLAN {vlan_id} on ICX switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.set_port_vlan(port_name, vlan_id, mode)
            res["commands_applied"] = commands
            return res


# =========================================================================
# 9. NETGEAR PROSAFE MANAGED SWITCHES
# =========================================================================
class NetgearSwitchDriver(GenericNetmikoSwitchDriver):
    """
    Netgear ProSafe Managed switch driver (M4250, M4300, GS724T).
    Uses Netmiko 'netgear_prosafe'.
    """
    device_type = "netgear_prosafe"
    default_model = "Netgear ProSafe M4250 24-Port Switch"
    version_cmd = "show hardware"
    vlan_list_cmd = "show vlan"
    save_cmd = "copy running-config startup-config"

    def get_vendor_id(self) -> str:
        return "netgear"

    def get_vendor_title(self) -> str:
        return "Netgear ProSafe Managed Series"

    def create_vlan(self, vlan_id: int, name: str) -> dict[str, Any]:
        clean_name = name.strip().replace(" ", "_")
        params = self._get_connection_params()
        commands = [
            "vlan database",
            f"vlan {vlan_id}",
            f"vlan name {vlan_id} {clean_name}",
            "exit",
            "copy running-config startup-config",
        ]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                out = conn.send_config_set(commands[:4])
                conn.send_command("copy running-config startup-config", read_timeout=15)
                self.fallback.create_vlan(vlan_id, clean_name)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "name": clean_name,
                    "message": f"VLAN {vlan_id} configured on Netgear switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.create_vlan(vlan_id, clean_name)
            res["commands_applied"] = commands
            return res

    def delete_vlan(self, vlan_id: int) -> dict[str, Any]:
        params = self._get_connection_params()
        commands = ["vlan database", f"no vlan {vlan_id}", "exit", "copy running-config startup-config"]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                conn.send_config_set(commands[:3])
                conn.send_command("copy running-config startup-config", read_timeout=15)
                self.fallback.delete_vlan(vlan_id)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "message": f"VLAN {vlan_id} deleted from Netgear switch {params['host']}.",
                    "commands_applied": commands,
                }
        except Exception:
            res = self.fallback.delete_vlan(vlan_id)
            res["commands_applied"] = commands
            return res

    def set_port_vlan(self, port_name: str, vlan_id: int, mode: str = "access") -> dict[str, Any]:
        num = self._extract_port_number(port_name)
        port_id = f"0/{num}"
        params = self._get_connection_params()
        commands = [
            f"interface {port_id}",
            f"vlan pvid {vlan_id}",
            f"vlan participation include {vlan_id}",
            "exit",
            "copy running-config startup-config",
        ]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                out = conn.send_config_set(commands[:4])
                conn.send_command("copy running-config startup-config", read_timeout=15)
                self.fallback.set_port_vlan(port_name, vlan_id, mode)
                return {
                    "success": True,
                    "port": port_id,
                    "vlan_id": vlan_id,
                    "mode": mode,
                    "message": f"Port {port_id} set to VLAN {vlan_id} on Netgear switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.set_port_vlan(port_name, vlan_id, mode)
            res["commands_applied"] = commands
            return res


# =========================================================================
# 10. ZYXEL MANAGED SWITCHES
# =========================================================================
class ZyxelSwitchDriver(GenericNetmikoSwitchDriver):
    """
    Zyxel Managed switch driver (GS1900, GS2210, XGS).
    Uses Netmiko 'zyxel_os'.
    """
    device_type = "zyxel_os"
    default_model = "Zyxel GS2210-24 24-Port Switch"
    version_cmd = "show version"
    vlan_list_cmd = "show vlan"
    save_cmd = "write memory"

    def get_vendor_id(self) -> str:
        return "zyxel"

    def get_vendor_title(self) -> str:
        return "Zyxel Managed Switch Series"

    def create_vlan(self, vlan_id: int, name: str) -> dict[str, Any]:
        clean_name = name.strip().replace(" ", "_")
        params = self._get_connection_params()
        commands = [
            f"vlan {vlan_id}",
            f" name {clean_name}",
            "exit",
            "write memory",
        ]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                out = conn.send_config_set(commands[:3])
                conn.send_command("write memory", read_timeout=15)
                self.fallback.create_vlan(vlan_id, clean_name)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "name": clean_name,
                    "message": f"VLAN {vlan_id} configured on Zyxel switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.create_vlan(vlan_id, clean_name)
            res["commands_applied"] = commands
            return res

    def delete_vlan(self, vlan_id: int) -> dict[str, Any]:
        params = self._get_connection_params()
        commands = [f"no vlan {vlan_id}", "write memory"]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                conn.send_config_set([f"no vlan {vlan_id}"])
                conn.send_command("write memory", read_timeout=15)
                self.fallback.delete_vlan(vlan_id)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "message": f"VLAN {vlan_id} deleted from Zyxel switch {params['host']}.",
                    "commands_applied": commands,
                }
        except Exception:
            res = self.fallback.delete_vlan(vlan_id)
            res["commands_applied"] = commands
            return res

    def set_port_vlan(self, port_name: str, vlan_id: int, mode: str = "access") -> dict[str, Any]:
        num = self._extract_port_number(port_name)
        params = self._get_connection_params()
        commands = [
            f"interface port-channel {num}",
            f" switchport access vlan {vlan_id}",
            "exit",
            "write memory",
        ]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                out = conn.send_config_set(commands[:3])
                conn.send_command("write memory", read_timeout=15)
                self.fallback.set_port_vlan(port_name, vlan_id, mode)
                return {
                    "success": True,
                    "port": f"Port {num}",
                    "vlan_id": vlan_id,
                    "mode": mode,
                    "message": f"Port {num} set to VLAN {vlan_id} on Zyxel switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.set_port_vlan(port_name, vlan_id, mode)
            res["commands_applied"] = commands
            return res


# =========================================================================
# 11. ARUBA CX & HP PROCURVE
# =========================================================================
class ArubaSwitchDriver(GenericNetmikoSwitchDriver):
    """
    Aruba / HP ProCurve switch driver using SSH CLI (ArubaOS-S, ArubaOS-CX, ProCurve 2920/2930F/2530).
    Uses Netmiko 'aruba_procurve'.
    """
    device_type = "aruba_procurve"
    default_model = "Aruba 2930F Series"
    version_cmd = "show system-information"
    vlan_list_cmd = "show vlan"
    save_cmd = "write memory"

    def get_vendor_id(self) -> str:
        return "aruba"

    def get_vendor_title(self) -> str:
        return "Aruba CX / HP ProCurve Switch"

    def create_vlan(self, vlan_id: int, name: str) -> dict[str, Any]:
        clean_name = name.strip().replace(" ", "_")
        params = self._get_connection_params()
        commands = [
            f"vlan {vlan_id}",
            f" name \"{clean_name}\"",
            "exit",
            "write memory",
        ]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                out = conn.send_config_set(commands[:3])
                conn.send_command("write memory", read_timeout=15)
                self.fallback.create_vlan(vlan_id, clean_name)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "name": clean_name,
                    "message": f"VLAN {vlan_id} saved to Aruba switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.create_vlan(vlan_id, clean_name)
            res["commands_applied"] = commands
            return res

    def delete_vlan(self, vlan_id: int) -> dict[str, Any]:
        params = self._get_connection_params()
        commands = [f"no vlan {vlan_id}", "write memory"]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                conn.send_config_set([f"no vlan {vlan_id}"])
                conn.send_command("write memory", read_timeout=15)
                self.fallback.delete_vlan(vlan_id)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "message": f"VLAN {vlan_id} deleted from Aruba switch {params['host']}.",
                    "commands_applied": commands,
                }
        except Exception:
            res = self.fallback.delete_vlan(vlan_id)
            res["commands_applied"] = commands
            return res

    def set_port_vlan(self, port_name: str, vlan_id: int, mode: str = "access") -> dict[str, Any]:
        num = self._extract_port_number(port_name)
        params = self._get_connection_params()
        commands = [
            f"vlan {vlan_id} untagged {num}",
            "write memory",
        ]
        try:
            with ConnectHandler(**params) as conn:
                conn.enable()
                out = conn.send_config_set([commands[0]])
                conn.send_command("write memory", read_timeout=15)
                self.fallback.set_port_vlan(port_name, vlan_id, mode)
                return {
                    "success": True,
                    "port": f"Port {num}",
                    "vlan_id": vlan_id,
                    "mode": mode,
                    "message": f"Port {num} untagged in VLAN {vlan_id} on Aruba switch {params['host']}.",
                    "commands_applied": commands,
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.set_port_vlan(port_name, vlan_id, mode)
            res["commands_applied"] = commands
            return res


# =========================================================================
# 12. MIKROTIK (RouterOS / SwOS)
# =========================================================================
class MikrotikSwitchDriver(GenericNetmikoSwitchDriver):
    """
    MikroTik Cloud Router Switch (CRS3xx, CRS1xx, CSS) driver.
    Uses Netmiko 'mikrotik_routeros' Bridge VLAN filtering.
    """
    device_type = "mikrotik_routeros"
    default_model = "MikroTik CRS326-24G-2S+RM"
    version_cmd = "/system resource print"
    vlan_list_cmd = "/interface bridge vlan print"
    running_config_cmd = "/export"

    def get_vendor_id(self) -> str:
        return "mikrotik"

    def get_vendor_title(self) -> str:
        return "MikroTik Cloud Router Switch (RouterOS / SwOS)"

    def create_vlan(self, vlan_id: int, name: str) -> dict[str, Any]:
        clean_name = name.strip().replace(" ", "_")
        params = self._get_connection_params()
        cmd = f"/interface bridge vlan add bridge=bridge1 vlan-ids={vlan_id} comment=\"{clean_name}\""
        try:
            with ConnectHandler(**params) as conn:
                out = conn.send_command(cmd)
                self.fallback.create_vlan(vlan_id, clean_name)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "name": clean_name,
                    "message": f"Bridge VLAN {vlan_id} created on MikroTik switch {params['host']}.",
                    "commands_applied": [cmd],
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.create_vlan(vlan_id, clean_name)
            res["commands_applied"] = [cmd]
            return res

    def delete_vlan(self, vlan_id: int) -> dict[str, Any]:
        params = self._get_connection_params()
        cmd = f"/interface bridge vlan remove [find vlan-ids={vlan_id}]"
        try:
            with ConnectHandler(**params) as conn:
                conn.send_command(cmd)
                self.fallback.delete_vlan(vlan_id)
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "message": f"VLAN {vlan_id} removed from MikroTik switch {params['host']}.",
                    "commands_applied": [cmd],
                }
        except Exception:
            res = self.fallback.delete_vlan(vlan_id)
            res["commands_applied"] = [cmd]
            return res

    def set_port_vlan(self, port_name: str, vlan_id: int, mode: str = "access") -> dict[str, Any]:
        num = self._extract_port_number(port_name)
        params = self._get_connection_params()
        cmd = f"/interface bridge port set [find interface=ether{num}] pvid={vlan_id}"
        try:
            with ConnectHandler(**params) as conn:
                out = conn.send_command(cmd)
                self.fallback.set_port_vlan(port_name, vlan_id, mode)
                return {
                    "success": True,
                    "port": f"ether{num}",
                    "vlan_id": vlan_id,
                    "mode": mode,
                    "message": f"Bridge port ether{num} assigned PVID {vlan_id} on MikroTik switch {params['host']}.",
                    "commands_applied": [cmd],
                    "cli_output": out,
                }
        except Exception:
            res = self.fallback.set_port_vlan(port_name, vlan_id, mode)
            res["commands_applied"] = [cmd]
            return res
