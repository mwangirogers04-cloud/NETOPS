import platform
import subprocess
import urllib.request
import urllib.error
import json
from datetime import datetime
import time

import os
import sys

def get_default_interface():
    """Determine the active default gateway network interface or fallback."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            check=False,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if "dev" in parts:
                dev_idx = parts.index("dev") + 1
                if dev_idx < len(parts):
                    return parts[dev_idx]
    except (FileNotFoundError, OSError):
        pass
    return "wlan0"


def get_mac_address():
    """Return the MAC address of the active network interface."""
    interface = get_default_interface()
    try:
        result = subprocess.run(
            [
                "ip",
                "link",
                "show",
                interface,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        for line in result.stdout.splitlines():
            line = line.strip()

            if line.startswith("link/ether"):
                return line.split()[1].upper()

        return None

    except (FileNotFoundError, OSError):
        return None

def get_ip_address():
    """Return the IPv4 address of the active network interface."""
    interface = get_default_interface()
    try:
        result = subprocess.run(
            [
                "ip",
                "-4",
                "addr",
                "show",
                interface,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        for line in result.stdout.splitlines():
            line = line.strip()

            if line.startswith("inet "):
                return line.split()[1].split("/")[0]

        return None

    except (FileNotFoundError, OSError):
        return None

def get_machine_id():
    """Return the Linux machine identifier."""
    try:
        with open("/etc/machine-id", "r", encoding="utf-8") as file:
            return file.read().strip()
    except (FileNotFoundError, OSError):
        return None


def get_system_info():
    """Return basic information about the endpoint."""
    return {
        "hostname": platform.node(),
        "mac_address": get_mac_address(),
        "ip_address": get_ip_address(),
        "operating_system": platform.system(),
        "os_version": platform.release(),
        "architecture": platform.machine(),
        "machine_id": get_machine_id(),
    }


def check_linux_updates():
    """Check Debian/Kali packages for pending updates."""
    try:
        result = subprocess.run(
            ["apt", "list", "--upgradable"],
            capture_output=True,
            text=True,
            check=False,
        )

        lines = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip() and not line.startswith("Listing...")
        ]

        return {
            "update_status": (
                "updates_available"
                if lines
                else "up_to_date"
            ),
            "pending_updates": len(lines),
            "security_updates": None,
        }

    except FileNotFoundError:
        return {
            "update_status": "unsupported",
            "pending_updates": 0,
            "security_updates": None,
        }

def get_server_url():
    """Determine the NETOPS server URL from CLI arg, ENV, or default."""
    for arg in sys.argv[1:]:
        if arg.startswith("http://") or arg.startswith("https://"):
            url = arg.rstrip("/")
            if not url.endswith("/endpoint-updates"):
                url += "/endpoint-updates/"
            return url

    env_url = os.environ.get("NETOPS_SERVER_URL")
    if env_url:
        url = env_url.rstrip("/")
        if not url.endswith("/endpoint-updates"):
            url += "/endpoint-updates/"
        return url

    return "http://127.0.0.1:8000/endpoint-updates/"


def send_update_status(information, server_url=None):
    """Send endpoint update status to the NETOPS backend."""
    api_url = server_url or get_server_url()

    data = json.dumps(information).encode("utf-8")

    request = urllib.request.Request(
        api_url,
        data=data,
        headers={
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response_data = response.read().decode("utf-8")
            return response_data

    except urllib.error.URLError as error:
        return f"Unable to contact NETOPS server at {api_url}: {error}"


def collect_update_status():
    """Collect the complete endpoint update status."""
    system_info = get_system_info()

    if system_info["operating_system"] == "Linux":
        update_info = check_linux_updates()
    else:
        update_info = {
            "update_status": "unsupported",
            "pending_updates": 0,
            "security_updates": None,
        }

    return {
        **system_info,
        **update_info,
        "last_checked": datetime.now().isoformat(),
    }


if __name__ == "__main__":
    REPORT_INTERVAL = 300
    run_once = "--once" in sys.argv

    while True:
        information = collect_update_status()

        print("\nNETOPS Endpoint Update Status")
        print("--------------------------------")

        for key, value in information.items():
            print(f"{key}: {value}")

        target_url = get_server_url()
        print(f"\nSending update status to NETOPS ({target_url})...")
        response = send_update_status(information, target_url)
        print(response)

        if run_once:
            break

        print(
            f"\nNext update check in "
            f"{REPORT_INTERVAL // 60} minutes..."
        )

        time.sleep(REPORT_INTERVAL)
