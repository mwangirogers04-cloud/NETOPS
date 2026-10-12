from ..models.device import Device


# ---------------------------------------------------------------------------
# Simulated Cisco switches
# ---------------------------------------------------------------------------
# These represent the Cisco switches that NETOPS will eventually communicate
# with through SSH/API in the production version.
#
# Current mode:
#     simulation
#
# No real switch configuration is performed.
# ---------------------------------------------------------------------------

SIMULATED_SWITCHES = [
    {
        "name": "CORE-SW01",
        "management_ip": "192.168.0.2",
        "model": "Cisco Catalyst 2960-X",
        "status": "online",
    },
    {
        "name": "ACCESS-SW01",
        "management_ip": "192.168.0.3",
        "model": "Cisco Catalyst 2960-X",
        "status": "online",
    },
]


# ---------------------------------------------------------------------------
# Simulated MAC address → switch port mapping
# ---------------------------------------------------------------------------
# In a real environment NETOPS will learn this information from the switch
# MAC address table.
#
# For development we simulate that information here.
# ---------------------------------------------------------------------------

SIMULATED_PORT_MAP = {
    "AA:BB:CC:DD:EE:11": {
        "switch_name": "CORE-SW01",
        "switch_port": "Gi0/10",
    },

    "AA:BB:CC:DD:EE:FF": {
        "switch_name": "CORE-SW01",
        "switch_port": "Gi0/11",
    },

    "AA:BB:CC:DD:EE:12": {
        "switch_name": "ACCESS-SW01",
        "switch_port": "Gi0/5",
    },

    "AA:BB:CC:DD:EE:13": {
        "switch_name": "ACCESS-SW01",
        "switch_port": "Gi0/6",
    },

    "AA:BB:CC:DD:EE:14": {
        "switch_name": "CORE-SW01",
        "switch_port": "Gi0/12",
    },

    # Printer device
    # IP: 192.168.0.50
    # MAC: AA:BB:CC:11:22:33
    # Required VLAN: 40
    "AA:BB:CC:11:22:33": {
        "switch_name": "ACCESS-SW01",
        "switch_port": "Gi0/8",
    },

    # CCTV device
    # IP: 192.168.0.102
    # MAC: A4:4E:31:AD:0E:28
    # Required VLAN: 30
    "A4:4E:31:AD:0E:28": {
        "switch_name": "ACCESS-SW01",
        "switch_port": "Gi0/7",
    },
}


def identify_switch_port(device: Device) -> dict:
    """
    Identify the simulated Cisco switch and port where a device is connected.

    Current development mode:
        - Uses the simulated MAC address table.
        - Does not communicate with a real Cisco switch.

    Future production mode:
        - NETOPS will query the actual Cisco switch MAC address table.
        - The discovered switch and port will then be used for VLAN
          configuration.
    """

    if not device.mac_address:
        return {
            "identified": False,
            "switch_name": None,
            "switch_port": None,
            "source": "simulation",
            "reason": "Device does not have a MAC address",
        }

    mac_address = (
        device.mac_address
        .upper()
        .strip()
    )

    mapping = SIMULATED_PORT_MAP.get(mac_address)

    if not mapping:
        return {
            "identified": False,
            "switch_name": None,
            "switch_port": None,
            "source": "simulation",
            "reason": (
                "Device MAC address not found "
                "in simulated switch table"
            ),
        }

    switch_name = mapping["switch_name"]
    switch_port = mapping["switch_port"]

    switch = next(
        (
            switch
            for switch in SIMULATED_SWITCHES
            if switch["name"] == switch_name
        ),
        None,
    )

    if switch is None:
        return {
            "identified": False,
            "switch_name": switch_name,
            "switch_port": switch_port,
            "source": "simulation",
            "reason": (
                "Switch port mapping exists, "
                "but the simulated switch does not exist"
            ),
        }

    if switch["status"] != "online":
        return {
            "identified": False,
            "switch_name": switch_name,
            "switch_port": switch_port,
            "source": "simulation",
            "reason": (
                f"Simulated switch {switch_name} "
                f"is currently {switch['status']}"
            ),
        }

    return {
        "identified": True,
        "switch_name": switch_name,
        "switch_port": switch_port,
        "source": "simulation",
        "reason": (
            "Device MAC address matched simulated "
            "switch MAC address table"
        ),
    }

def identify_switch_port_from_mac_table(
    device: Device,
    mac_table: list[dict],
    switch_name: str,
) -> dict:
    """
    Identify a device's MAC address in a supplied Cisco
    MAC address table.

    This function only processes data already retrieved.
    It does not connect to or configure a switch.
    """

    if not device.mac_address:
        return {
            "identified": False,
            "switch_name": None,
            "switch_port": None,
            "source": "supplied_mac_table",
            "reason": "Device does not have a MAC address",
        }

    target_mac = (
        device.mac_address
        .strip()
        .replace("-", ":")
        .replace(".", "")
        .upper()
    )

    if ":" in target_mac:
        target_mac = target_mac.replace(":", "")

    matches = []

    for entry in mac_table:
        raw_mac = str(entry.get("mac_address", ""))
        candidate_mac = (
            raw_mac
            .strip()
            .replace("-", "")
            .replace(":", "")
            .replace(".", "")
            .upper()
        )

        if candidate_mac == target_mac:
            matches.append(entry)

    if not matches:
        return {
            "identified": False,
            "switch_name": switch_name,
            "switch_port": None,
            "source": "supplied_mac_table",
            "reason": "Device MAC address not found in supplied MAC table",
        }

    interfaces = {
        str(entry.get("interface", "")).strip()
        for entry in matches
        if entry.get("interface")
    }

    vlans = {
        entry.get("vlan_id")
        for entry in matches
    }

    if (
        len(interfaces) != 1
        or len(vlans) != 1
        or None in vlans
    ):
        return {
            "identified": False,
            "switch_name": switch_name,
            "switch_port": None,
            "source": "supplied_mac_table",
            "reason": (
                "MAC address has missing or conflicting "
                "interface or VLAN entries"
            ),
        }

    switch_port = interfaces.pop()

    return {
        "identified": True,
        "switch_name": switch_name,
        "switch_port": switch_port,
        "source": "supplied_mac_table",
        "reason": "Device MAC address matched the supplied Cisco MAC table",
        "vlan_id": next(iter(vlans)),
    }

