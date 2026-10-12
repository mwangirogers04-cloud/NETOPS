import platform
import subprocess
import urllib.request
import urllib.error
import json
from datetime import datetime
import time

def get_machine_id():
    """Return the Windows machine identifier."""
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "(Get-ItemProperty "
                    "-Path 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography' "
                    "-Name MachineGuid).MachineGuid"
                ),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        machine_id = result.stdout.strip()

        return machine_id or None

    except (FileNotFoundError, OSError):
        return None

def get_network_info():
    """Return the IPv4 and MAC address of the active network."""
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                (
                    "$c = Get-NetIPConfiguration | "
                    "Where-Object { $_.IPv4DefaultGateway -ne $null } | "
                    "Select-Object -First 1; "
                    "if ($c) { "
                    "$a = Get-NetAdapter -InterfaceIndex $c.InterfaceIndex; "
                    "[PSCustomObject]@{ "
                    "mac_address = $a.MacAddress; "
                    "ip_address = @($c.IPv4Address)[0].IPAddress "
                    "} | ConvertTo-Json -Compress "
                    "}"
                ),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )

        if result.returncode != 0 or not result.stdout.strip():
            return {"mac_address": None, "ip_address": None}

        network_info = json.loads(result.stdout.strip())

        return {
            "mac_address": network_info.get("mac_address"),
            "ip_address": network_info.get("ip_address"),
        }

    except (
        FileNotFoundError,
        OSError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
    ):
        return {"mac_address": None, "ip_address": None}


def get_system_info():
    """Return basic information about the Windows endpoint."""
    return {
        "hostname": platform.node(),
        "operating_system": platform.system(),
        "os_version": platform.release(),
        "architecture": platform.machine(),
        "machine_id": get_machine_id(),
        **get_network_info(),
    }


def check_windows_updates():
    """Check pending updates using the built-in Windows Update Agent."""

    if platform.system() != "Windows":
        return {
            "update_status": "unsupported",
            "pending_updates": 0,
            "security_updates": None,
        }

    powershell_script = r"""
$ErrorActionPreference = 'Stop'
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result = $searcher.Search("IsInstalled=0 and IsHidden=0")
    Write-Output ([int]$result.Updates.Count)
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
"""

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                powershell_script,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )

        output = result.stdout.strip()

        if result.returncode != 0 or not output.isdigit():
            return {
                "update_status": "error",
                "pending_updates": 0,
                "security_updates": None,
            }

        pending_updates = int(output)

        return {
            "update_status": (
                "updates_available"
                if pending_updates > 0
                else "up_to_date"
            ),
            "pending_updates": pending_updates,
            "security_updates": None,
        }

    except subprocess.TimeoutExpired:
        return {
            "update_status": "error",
            "pending_updates": 0,
            "security_updates": None,
        }
    except (FileNotFoundError, OSError):
        return {
            "update_status": "unsupported",
            "pending_updates": 0,
            "security_updates": None,
        }


def collect_update_status():
    """Collect Windows system and update information."""
    system_info = get_system_info()
    update_info = check_windows_updates()

    return {
        **system_info,
        **update_info,
    }


def send_update_status(data):
    """Send Windows endpoint update status to the NETOPS backend."""
    url = "http://192.168.0.101:8000/endpoint-updates/"

    payload = json.dumps(data).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.read().decode("utf-8")

    except urllib.error.URLError as error:
        return f"Connection error: {error}"

    except Exception as error:
        return f"Error sending update status: {error}"



if __name__ == "__main__":
    REPORT_INTERVAL = 300  # 5 minutes

    while True:
        try:
            information = collect_update_status()

            print("\nNETOPS Windows Endpoint")
            print("--------------------------------")

            for key, value in information.items():
                print(f"{key}: {value}")

            print("\nSending update status to NETOPS...")
            response = send_update_status(information)
            print(response)

        except Exception as error:
            print(f"Endpoint monitoring error: {error}")

        print(
            f"\nNext update check in "
            f"{REPORT_INTERVAL // 60} minutes..."
        )

        time.sleep(REPORT_INTERVAL)


















