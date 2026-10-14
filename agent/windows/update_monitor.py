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


import os
import sys

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

    return "http://192.168.0.101:8000/endpoint-updates/"


def send_update_status(data, server_url=None):
    """Send Windows endpoint update status to the NETOPS backend."""
    url = server_url or get_server_url()

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


def report_job_status(job_id, status, progress_percent=None, log_output=None, error_message=None, server_url=None):
    """Report Windows update execution progress back to NETOPS."""
    base_url = (server_url or get_server_url()).rstrip("/")
    if base_url.endswith("/endpoint-updates"):
        status_url = f"{base_url}/jobs/{job_id}/status"
    else:
        status_url = f"{base_url}/endpoint-updates/jobs/{job_id}/status"

    payload = {
        "status": status,
        "progress_percent": progress_percent,
        "log_output": log_output,
        "error_message": error_message,
    }
    req = urllib.request.Request(
        status_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read().decode("utf-8")
    except Exception as err:
        print(f"Warning: Failed to report Windows job status to NETOPS: {err}")
        return None


def execute_patch_job(job_id, action, server_url=None):
    """Execute Windows Update installation requested by NETOPS central console."""
    print(f"\n[NETOPS INSTRUCTION] Received remote update command: Job #{job_id} ({action})")
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report_job_status(
        job_id=job_id,
        status="IN_PROGRESS",
        progress_percent=25,
        log_output=f"[{now_str}] Windows agent accepted patch job #{job_id}. Initializing Windows Update session...",
        server_url=server_url,
    )

    ps_script = r"""
$ErrorActionPreference = 'Continue'
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result = $searcher.Search("IsInstalled=0 and IsHidden=0")
    if ($result.Updates.Count -eq 0) {
        Write-Output "No pending updates found."
        exit 0
    }
    Write-Output "Found $($result.Updates.Count) updates to install."
    $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($update in $result.Updates) {
        $updatesToInstall.Add($update) | Out-Null
    }
    $downloader = $session.CreateUpdateDownloader()
    $downloader.Updates = $updatesToInstall
    $downloader.Download()
    $installer = $session.CreateUpdateInstaller()
    $installer.Updates = $updatesToInstall
    $res = $installer.Install()
    Write-Output "Installation complete. ResultCode: $($res.ResultCode)"
} catch {
    # Fallback to USOClient command
    Start-Process usoclient.exe StartInteractiveScan
    Write-Output "Triggered USOClient interactive update scan."
}
"""
    try:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_job_status(
            job_id=job_id,
            status="IN_PROGRESS",
            progress_percent=60,
            log_output=f"[{now_str}] Downloading and applying Windows Updates via WUA...",
            server_url=server_url,
        )

        res = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                ps_script,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=900,
        )

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        output = res.stdout.strip() or res.stderr.strip()
        print(f"[NETOPS] Windows update completed: {output}")

        report_job_status(
            job_id=job_id,
            status="COMPLETED",
            progress_percent=100,
            log_output=f"[{now_str}] Windows Update finished: {output[-300:]}",
            server_url=server_url,
        )

    except Exception as exc:
        print(f"[NETOPS] Windows patch execution failed: {exc}")
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_job_status(
            job_id=job_id,
            status="FAILED",
            error_message=str(exc),
            log_output=f"[{now_str}] Windows execution error: {exc}",
            server_url=server_url,
        )


if __name__ == "__main__":
    REPORT_INTERVAL = 300  # 5 minutes
    run_once = "--once" in sys.argv

    while True:
        try:
            information = collect_update_status()

            print("\nNETOPS Windows Endpoint")
            print("--------------------------------")

            for key, value in information.items():
                print(f"{key}: {value}")

            target_url = get_server_url()
            print(f"\nSending update status to NETOPS ({target_url})...")
            response = send_update_status(information, target_url)
            print(response)

            # Process central remediation instructions
            try:
                resp_json = json.loads(response)
                if isinstance(resp_json, dict) and resp_json.get("pending_command"):
                    cmd = resp_json["pending_command"]
                    execute_patch_job(cmd["job_id"], cmd["action"], target_url)
                    # Refresh and send updated status
                    fresh_info = collect_update_status()
                    send_update_status(fresh_info, target_url)
            except Exception as proc_err:
                print(f"Instruction processing notice: {proc_err}")

        except Exception as error:
            print(f"Endpoint monitoring error: {error}")

        if run_once:
            break

        print(
            f"\nNext update check in "
            f"{REPORT_INTERVAL // 60} minutes..."
        )

        time.sleep(REPORT_INTERVAL)


















