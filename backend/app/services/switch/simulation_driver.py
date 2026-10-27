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
    """

    _vlans_cache: list[dict[str, Any]] = []
    _ports_cache: list[dict[str, Any]] = []

    def __init__(self, config: Any | None = None):
        super().__init__(config)
        self._init_state()

    @classmethod
    def _init_state(cls):
        if not cls._vlans_cache:
            cls._vlans_cache = [dict(v) for v in DEFAULT_SIMULATED_VLANS]

        if not cls._ports_cache:
            ports = []
            for i in range(1, 25):
                name = f"GigabitEthernet0/{i}"
                short_name = f"Gi0/{i}"
                vlan = 20
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
                    "allowed_vlans": "ALL (1-4094)" if is_uplink else f"VLAN {vlan}",
                    "connected_mac": f"AA:BB:CC:DD:EE:{i:02X}" if status == "connected" else None,
                })
            cls._ports_cache = ports

    def get_vendor_id(self) -> str:
        return "simulation"

    def get_vendor_title(self) -> str:
        return "Software Switch Simulator (Netmiko/Cisco Emulation)"

    def test_connection(self) -> dict[str, Any]:
        return {
            "success": True,
            "status": "connected",
            "message": "Successfully connected to Simulated Switch (Cisco IOS-XE Emulation)",
            "vendor": "simulation",
            "switch_model": "Cisco Catalyst 2960-X (Simulated)",
            "version": "15.2(7)E3",
            "total_ports": 24,
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
        model = getattr(self.config, "model", "WS-C2960X-24TS-L") or "WS-C2960X-24TS-L"

        lines = [
            f"! Current configuration : Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E7",
            f"! Technical Support: http://www.cisco.com/techsupport",
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
