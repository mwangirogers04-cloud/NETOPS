import logging
from typing import Any
from .base import BaseSwitchDriver

logger = logging.getLogger(__name__)

# Pre-seeded default corporate VLANs
DEFAULT_SIMULATED_VLANS = [
    {"vlan_id": 1, "name": "default", "status": "active", "ports": "Gi0/21, Gi0/22, Gi0/23, Gi0/24"},
    {"vlan_id": 10, "name": "VOIP_PHONES", "status": "active", "ports": "Gi0/1, Gi0/2, Gi0/3"},
    {"vlan_id": 20, "name": "COMPUTERS", "status": "active", "ports": "Gi0/4, Gi0/5, Gi0/6, Gi0/7, Gi0/8"},
    {"vlan_id": 30, "name": "CCTV_CAMERAS", "status": "active", "ports": "Gi0/9, Gi0/10"},
    {"vlan_id": 40, "name": "PRINTERS", "status": "active", "ports": "Gi0/11, Gi0/12"},
    {"vlan_id": 50, "name": "SERVERS", "status": "active", "ports": "Gi0/13, Gi0/14"},
    {"vlan_id": 60, "name": "WIFI_ACCESS_POINTS", "status": "active", "ports": "Gi0/15, Gi0/16"},
    {"vlan_id": 90, "name": "QUARANTINE", "status": "active", "ports": "Gi0/17, Gi0/18"},
]


class SimulationSwitchDriver(BaseSwitchDriver):
    """
    Simulated switch driver providing in-memory state for development,
    demonstration, and environments where physical switch hardware is offline.
    Supports dynamic chassis density: 24-Port and 48-Port Enterprise layouts.
    """

    _vlans_cache: list[dict[str, Any]] = []
    _ports_cache: list[dict[str, Any]] = []
    _current_density: int = 24

    def __init__(self, config: Any | None = None):
        super().__init__(config)
        if config:
            if isinstance(config, dict):
                density = config.get("total_ports") or self.__class__._current_density
            else:
                density = getattr(config, "total_ports", None) or self.__class__._current_density
        else:
            density = self.__class__._current_density
        density = 48 if density == 48 else 24
        self._init_state(density)

    @classmethod
    def generate_simulated_ports(cls, total_ports: int = 24) -> list[dict[str, Any]]:
        ports = []
        if total_ports == 48:
            # 48 Gigabit Ethernet ports (Gi0/1 - Gi0/48)
            for i in range(1, 49):
                name = f"GigabitEthernet0/{i}"
                short_name = f"Gi0/{i}"
                if 1 <= i <= 6:
                    vlan = 10
                elif 7 <= i <= 24:
                    vlan = 20
                elif 25 <= i <= 28:
                    vlan = 30
                elif 29 <= i <= 32:
                    vlan = 40
                elif 33 <= i <= 38:
                    vlan = 50
                elif 39 <= i <= 42:
                    vlan = 60
                elif 43 <= i <= 44:
                    vlan = 90
                else:
                    vlan = 1

                # Ports 47 and 48 are default copper trunk uplinks
                is_uplink = (i in (47, 48))
                mode = "trunk" if is_uplink else "access"
                status = "connected" if (i <= 28 or is_uplink) else "notconnect"
                ports.append({
                    "port": name,
                    "short_name": short_name,
                    "status": status,
                    "vlan": vlan,
                    "duplex": "a-full" if status == "connected" else "auto",
                    "speed": "a-1000" if status == "connected" else "auto",
                    "type": "10/100/1000BaseTX",
                    "mode": mode,
                    "is_uplink": is_uplink,
                    "is_sfp": False,
                    "allowed_vlans": "ALL (1-4094)" if is_uplink else f"VLAN {vlan}",
                    "connected_mac": f"AA:BB:CC:DD:EE:{i:02X}" if status == "connected" else None,
                })

            # 4 SFP+ 10-Gigabit Uplink Cages (Te0/49 .. Te0/52)
            for j, sfp_id in enumerate(range(49, 53), start=1):
                name = f"TenGigabitEthernet0/{sfp_id}"
                short_name = f"Te0/{sfp_id}"
                sfp_status = "connected" if j <= 2 else "notconnect"
                ports.append({
                    "port": name,
                    "short_name": short_name,
                    "status": sfp_status,
                    "vlan": 1,
                    "duplex": "full" if sfp_status == "connected" else "auto",
                    "speed": "10000" if sfp_status == "connected" else "auto",
                    "type": "10GBase-SR/LR SFP+",
                    "mode": "trunk",
                    "is_uplink": True,
                    "is_sfp": True,
                    "allowed_vlans": "ALL (1-4094)",
                    "connected_mac": f"CC:10:DE:AD:00:{sfp_id:02X}" if sfp_status == "connected" else None,
                })
        else:
            # 24 Gigabit Ethernet ports (Gi0/1 - Gi0/24)
            for i in range(1, 25):
                name = f"GigabitEthernet0/{i}"
                short_name = f"Gi0/{i}"
                if i in (1, 2, 3):
                    vlan = 10
                elif i in (4, 5, 6, 7, 8):
                    vlan = 20
                elif i in (9, 10):
                    vlan = 30
                elif i in (11, 12):
                    vlan = 40
                elif i in (13, 14):
                    vlan = 50
                elif i in (15, 16):
                    vlan = 60
                elif i in (17, 18):
                    vlan = 90
                else:
                    vlan = 1

                # Last two ports (23 and 24) default as Uplink Trunk ports
                is_uplink = (i in (23, 24))
                mode = "trunk" if is_uplink else "access"
                status = "connected" if (i <= 14 or is_uplink) else "notconnect"
                ports.append({
                    "port": name,
                    "short_name": short_name,
                    "status": status,
                    "vlan": vlan,
                    "duplex": "a-full" if status == "connected" else "auto",
                    "speed": "a-1000" if status == "connected" else "auto",
                    "type": "10/100/1000BaseTX",
                    "mode": mode,
                    "is_uplink": is_uplink,
                    "is_sfp": False,
                    "allowed_vlans": "ALL (1-4094)" if is_uplink else f"VLAN {vlan}",
                    "connected_mac": f"AA:BB:CC:DD:EE:{i:02X}" if status == "connected" else None,
                })
        return ports

    @classmethod
    def reprovision_ports(cls, total_ports: int = 24):
        """Reprovision the in-memory switch ports cache to match 24 or 48 ports."""
        total_ports = 48 if total_ports == 48 else 24
        cls._current_density = total_ports
        cls._ports_cache = cls.generate_simulated_ports(total_ports)

    @classmethod
    def _init_state(cls, requested_ports: int = 24):
        if not cls._vlans_cache:
            cls._vlans_cache = [dict(v) for v in DEFAULT_SIMULATED_VLANS]

        if not cls._ports_cache or cls._current_density != requested_ports:
            cls.reprovision_ports(requested_ports)

    def get_total_ports(self) -> int:
        return getattr(self.__class__, "_current_density", 24) or 24

    def get_vendor_id(self) -> str:
        return "simulation"

    def get_vendor_title(self) -> str:
        density = self.get_total_ports()
        return f"Software Switch Simulator (Netmiko/Cisco Emulation - {density} Ports)"

    def test_connection(self) -> dict[str, Any]:
        density = self.get_total_ports()
        model_name = "Cisco Catalyst 2960X-48TS-L (Simulated)" if density == 48 else "Cisco Catalyst 2960-X (Simulated)"
        return {
            "success": True,
            "status": "connected",
            "message": f"Successfully connected to Simulated Switch (Cisco IOS-XE Emulation - {density}-Port Chassis)",
            "vendor": "simulation",
            "switch_model": model_name,
            "version": "15.2(7)E3",
            "total_ports": density,
            "vlans_count": len(self._vlans_cache),
        }

    def get_vlans(self) -> list[dict[str, Any]]:
        return list(self._vlans_cache)

    def create_vlan(self, vlan_id: int, name: str) -> dict[str, Any]:
        clean_name = name.strip().replace(" ", "_")
        for v in self._vlans_cache:
            if v["vlan_id"] == vlan_id:
                v["name"] = clean_name
                return {
                    "success": True,
                    "vlan_id": vlan_id,
                    "name": clean_name,
                    "action": "updated",
                    "message": f"VLAN {vlan_id} ('{clean_name}') successfully updated on switch.",
                    "commands_applied": [f"vlan {vlan_id}", f" name {clean_name}", "end", "write memory"],
                }

        new_vlan = {
            "vlan_id": vlan_id,
            "name": clean_name,
            "status": "active",
            "ports": "",
        }
        self._vlans_cache.append(new_vlan)
        return {
            "success": True,
            "vlan_id": vlan_id,
            "name": clean_name,
            "action": "created",
            "message": f"VLAN {vlan_id} ('{clean_name}') successfully created on switch.",
            "commands_applied": [f"vlan {vlan_id}", f" name {clean_name}", "end", "write memory"],
        }

    def delete_vlan(self, vlan_id: int) -> dict[str, Any]:
        if vlan_id in (1, 1002, 1003, 1004, 1005):
            raise ValueError(f"Cannot delete reserved default VLAN {vlan_id}.")

        before_len = len(self._vlans_cache)
        self._vlans_cache = [v for v in self._vlans_cache if v["vlan_id"] != vlan_id]

        # Reset any ports using this deleted VLAN back to VLAN 1
        for p in self._ports_cache:
            if p["vlan"] == vlan_id:
                p["vlan"] = 1

        return {
            "success": len(self._vlans_cache) < before_len,
            "vlan_id": vlan_id,
            "message": f"VLAN {vlan_id} removed from switch configuration.",
            "commands_applied": [f"no vlan {vlan_id}", "end", "write memory"],
        }

    def get_interfaces(self) -> list[dict[str, Any]]:
        return list(self._ports_cache)

    def set_port_vlan(
        self,
        port_name: str,
        vlan_id: int,
        mode: str = "access",
    ) -> dict[str, Any]:
        clean_port = port_name.strip()
        is_trunk = (mode.lower() == "trunk")
        matched = False
        for p in self._ports_cache:
            if (
                p["port"].lower() == clean_port.lower()
                or p["short_name"].lower() == clean_port.lower()
                or clean_port.lower().endswith(p["short_name"].lower())
            ):
                p["vlan"] = vlan_id
                p["mode"] = "trunk" if is_trunk else "access"
                p["is_uplink"] = is_trunk or p.get("is_uplink", False)
                p["allowed_vlans"] = "ALL (1-4094)" if is_trunk else f"VLAN {vlan_id}"
                matched = True
                clean_port = p["port"]
                break

        if not matched:
            # Add port dynamically if not found
            self._ports_cache.append({
                "port": clean_port,
                "short_name": clean_port.split("/")[-1] if "/" in clean_port else clean_port,
                "status": "connected",
                "vlan": vlan_id,
                "duplex": "a-full",
                "speed": "a-1000",
                "type": "10/100/1000BaseTX",
                "mode": "trunk" if is_trunk else "access",
                "is_uplink": is_trunk,
                "allowed_vlans": "ALL (1-4094)" if is_trunk else f"VLAN {vlan_id}",
                "connected_mac": None,
            })

        if is_trunk:
            cmds = [
                f"interface {clean_port}",
                " switchport trunk encapsulation dot1q",
                " switchport mode trunk",
                f" switchport trunk native vlan {vlan_id}",
                " switchport trunk allowed vlan all",
                "end",
                "write memory",
            ]
            msg = f"Port {clean_port} configured as 802.1Q Trunk Uplink (Native VLAN {vlan_id}, all VLANs allowed)."
        else:
            cmds = [
                f"interface {clean_port}",
                " switchport mode access",
                f" switchport access vlan {vlan_id}",
                "end",
                "write memory",
            ]
            msg = f"Port {clean_port} configured as Access port for VLAN {vlan_id}."

        return {
            "success": True,
            "port": clean_port,
            "vlan_id": vlan_id,
            "mode": "trunk" if is_trunk else "access",
            "is_uplink": is_trunk,
            "message": msg,
            "commands_applied": cmds,
        }

    def get_running_config(self) -> str:
        """
        Generate a realistic Cisco IOS running-config representing the current state
        of the switch including active VLAN database, trunk and access interfaces.
        """
        switch_name = getattr(self.config, "name", "Core-Switch-1") or "Core-Switch-1"
        hostname = switch_name.replace(" ", "-").replace("(", "").replace(")", "").upper()
        mgmt_ip = getattr(self.config, "management_ip", "192.168.0.2") or "192.168.0.2"
        density = self.get_total_ports()
        default_model = "WS-C2960X-48TS-L" if density == 48 else "WS-C2960X-24TS-L"
        model = getattr(self.config, "model", None) or default_model

        lines = [
            f"! Current configuration : Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E7",
            f"! Technical Support: http://www.cisco.com/techsupport",
            f"! Device Model: {model} ({density} Ports)",
            f"! Managed by NETOPS Network Operations Platform",
            f"!",
            f"version 15.2",
            f"no service pad",
            f"service timestamps debug datetime msec",
            f"service timestamps log datetime msec",
            f"service password-encryption",
            f"!",
            f"hostname {hostname}",
            f"!",
            f"boot-start-marker",
            f"boot-end-marker",
            f"!",
            f"spanning-tree mode rapid-pvst",
            f"spanning-tree extend system-id",
            f"!",
        ]

        # Add VLAN definitions
        vlans = self.get_vlans()
        for v in vlans:
            v_id = v.get("vlan_id")
            v_name = v.get("name", f"VLAN{v_id}")
            if v_id and v_id != 1:
                lines.append(f"vlan {v_id}")
                lines.append(f" name {v_name}")
                lines.append(f" state active")
                lines.append(f"!")

        # Add physical interface configurations
        ports = self.get_interfaces()
        for p in ports:
            port_name = p.get("port", "GigabitEthernet0/1")
            vlan = p.get("vlan", 1)
            is_trunk = (p.get("mode") == "trunk" or port_name in ("GigabitEthernet0/23", "GigabitEthernet0/24", "Gi0/23", "Gi0/24"))
            lines.append(f"interface {port_name}")
            if is_trunk:
                lines.append(f" description Uplink to Distribution / Firewall")
                lines.append(f" switchport trunk encapsulation dot1q")
                lines.append(f" switchport mode trunk")
                lines.append(f" switchport trunk native vlan {vlan}")
                lines.append(f" switchport trunk allowed vlan all")
            else:
                lines.append(f" description Workstation / Endpoint Port")
                lines.append(f" switchport mode access")
                lines.append(f" switchport access vlan {vlan}")
                lines.append(f" spanning-tree portfast")
                lines.append(f" spanning-tree bpduguard enable")
            lines.append(f"!")

        # Add management interface, SSH, and line vty
        lines.extend([
            f"interface Vlan1",
            f" description In-Band Network Management",
            f" ip address {mgmt_ip} 255.255.255.0",
            f" no shutdown",
            f"!",
            f"ip default-gateway 192.168.0.1",
            f"ip forward-protocol nd",
            f"ip http server",
            f"ip http secure-server",
            f"ip ssh version 2",
            f"!",
            f"banner motd ^C",
            f"===========================================================",
            f" NETOPS MANAGED DEVICE - UNAUTHORIZED ACCESS IS PROHIBITED",
            f" All configuration changes are audited and tracked.",
            f"===========================================================",
            f"^C",
            f"!",
            f"line con 0",
            f" logging synchronous",
            f"line vty 0 4",
            f" transport input ssh",
            f" login local",
            f"line vty 5 15",
            f" transport input ssh",
            f" login local",
            f"!",
            f"end",
        ])

        return "\n".join(lines) + "\n"
