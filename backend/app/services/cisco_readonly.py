import ipaddress
import os
import re
from typing import Any

from netmiko import ConnectHandler


def _get_credentials() -> dict[str, str]:
    username = os.getenv("NETOPS_SWITCH_USERNAME")
    password = os.getenv("NETOPS_SWITCH_PASSWORD")
    secret = os.getenv("NETOPS_SWITCH_ENABLE_SECRET", "")

    if not username or not password:
        raise RuntimeError(
            "Cisco credentials are not configured. "
            "Set NETOPS_SWITCH_USERNAME and "
            "NETOPS_SWITCH_PASSWORD."
        )

    return {
        "username": username,
        "password": password,
        "secret": secret,
    }


def connect_readonly(management_ip: str) -> Any:
    """
    Establish a connection to a Cisco IOS switch.

    This connection is currently intended for read-only
    operational commands.
    """
    try:
        management_ip = str(
            ipaddress.ip_address(management_ip)
        )
    except ValueError as exc:
        raise ValueError(
            "A valid switch management IP address is required."
        ) from exc

    allowed_ips = {
        item.strip()
        for item in os.getenv(
            "NETOPS_SWITCH_ALLOWED_IPS", ""
        ).split(",")
        if item.strip()
    }

    if management_ip not in allowed_ips:
        raise PermissionError(
            "Switch management IP is not on the approved list."
        )
    credentials = _get_credentials()

    device = {
        "device_type": "cisco_ios",
        "host": management_ip,
        "username": credentials["username"],
        "password": credentials["password"],
        "secret": credentials["secret"],
        "fast_cli": False,
    }

    return ConnectHandler(**device)


def get_mac_address_table(
    management_ip: str,
) -> list[dict[str, str | int]]:
    """
    Retrieve and parse the Cisco MAC address table.

    Only a read-only operational command is executed.
    """

    connection = connect_readonly(management_ip)

    try:
        output = connection.send_command(
            "show mac address-table",
            read_timeout=30,
        )
    finally:
        connection.disconnect()

    return parse_mac_address_table(output)



def get_interface_status(
    management_ip: str,
) -> str:
    """
    Retrieve interface status.

    READ-ONLY.
    """

    connection = connect_readonly(management_ip)

    try:
        return connection.send_command(
            "show interfaces status",
            read_timeout=30,
        )
    finally:
        connection.disconnect()


def get_vlan_brief(
    management_ip: str,
) -> str:
    """
    Retrieve VLAN information.

    READ-ONLY.
    """

    connection = connect_readonly(management_ip)

    try:
        return connection.send_command(
            "show vlan brief",
            read_timeout=30,
        )
    finally:
        connection.disconnect()

def parse_mac_address_table(
    output: str,
) -> list[dict[str, str | int]]:
    """
    Parse Cisco IOS MAC address table output.

    Returns normalized MAC addresses, VLAN IDs,
    entry types, and switch interfaces.
    """

    results: list[dict[str, str | int]] = []

    pattern = re.compile(
        r"^\s*(\d+)\s+"
        r"([0-9a-fA-F.:-]+)\s+"
        r"(DYNAMIC|STATIC)\s+"
        r"(\S+)\s*$",
        re.IGNORECASE,
    )

    for line in output.splitlines():
        match = pattern.match(line)

        if not match:
            continue

        vlan_id = int(match.group(1))
        raw_mac = match.group(2)
        entry_type = match.group(3).upper()
        interface = match.group(4)

        hex_mac = re.sub(r"[^0-9a-fA-F]", "", raw_mac)

        if len(hex_mac) != 12:
            continue
        normalized_mac = ":".join(
            hex_mac[i:i + 2].upper()
            for i in range(0, 12, 2)
        )

        results.append(
            {
                "vlan_id": vlan_id,
                "mac_address": normalized_mac,
                "interface": interface,
                "entry_type": entry_type,
            }
        )

    return results
