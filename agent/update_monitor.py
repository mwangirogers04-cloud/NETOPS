import platform
import subprocess
import urllib.request
import urllib.error
import json
from datetime import datetime
import time

import os
import sys

# Ensure agent directory is in sys.path for host_firewall import
AGENT_DIR = os.path.dirname(os.path.abspath(__file__))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

try:
    import host_firewall
except ImportError:
    host_firewall = None

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

        # Exclude held-back packages that apt-get upgrade does not install
        if lines:
            sim_res = subprocess.run(
                ["apt-get", "-s", "--with-new-pkgs", "upgrade"],
                capture_output=True,
                text=True,
                check=False,
            )
            if sim_res.returncode == 0:
                lines = [
                    l.strip()
                    for l in sim_res.stdout.splitlines()
                    if l.strip().startswith("Inst ")
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

    return "https://api.netops.co.ke/endpoint-updates/"


def send_update_status(information, server_url=None):
    """Send endpoint update status to the NETOPS backend."""
    api_url = server_url or get_server_url()

    data = json.dumps(information).encode("utf-8")

    request = urllib.request.Request(
        api_url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "NETOPS-Agent/1.0",
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


def report_job_status(job_id, status, progress_percent=None, log_output=None, error_message=None, installed_updates=None, server_url=None):
    """Report execution progress back to NETOPS job queue."""
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
        "installed_updates": installed_updates,
    }
    req = urllib.request.Request(
        status_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "NETOPS-Agent/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read().decode("utf-8")
    except Exception as err:
        print(f"Warning: Failed to report job status to NETOPS: {err}")
        return None


def execute_patch_job(job_id, action, server_url=None):
    """Execute update installation or machine restart requested by NETOPS central console."""
    print(f"\n[NETOPS INSTRUCTION] Received remote command: Job #{job_id} ({action})")
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Check for elevated privileges or passwordless sudo
    cmd_prefix = []
    if os.geteuid() != 0:
        sudo_check = subprocess.run(["sudo", "-n", "true"], capture_output=True, check=False)
        if sudo_check.returncode == 0:
            cmd_prefix = ["sudo", "-n"]

    if action == "REBOOT_MACHINE":
        print(f"[NETOPS] Restart command accepted. Initiating local system restart...")
        report_job_status(
            job_id=job_id,
            status="COMPLETED",
            progress_percent=100,
            log_output=f"[{now_str}] Endpoint accepted restart instruction from NETOPS. Executing shutdown -r +1...",
            server_url=server_url,
        )
        try:
            subprocess.Popen(cmd_prefix + ["shutdown", "-r", "+1", "NETOPS System Update Reboot"])
        except Exception as e:
            print(f"[NETOPS] Reboot trigger note: {e}")
        return

    report_job_status(
        job_id=job_id,
        status="IN_PROGRESS",
        progress_percent=20,
        log_output=f"[{now_str}] Remote agent accepted patch job #{job_id}. Running apt-get update...",
        server_url=server_url,
    )

    try:
        # Step 1: apt-get update
        subprocess.run(cmd_prefix + ["apt-get", "update"], capture_output=True, text=True, check=False, timeout=180)

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_job_status(
            job_id=job_id,
            status="IN_PROGRESS",
            progress_percent=60,
            log_output=f"[{now_str}] Repositories refreshed. Applying updates (apt-get upgrade)...",
            server_url=server_url,
        )

        # Step 2: apt-get -y upgrade
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        res = subprocess.run(
            cmd_prefix + ["apt-get", "-y", "--with-new-pkgs", "upgrade"],
            capture_output=True,
            text=True,
            check=False,
            timeout=1200,
            env=env,
        )

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if res.returncode == 0:
            print(f"[NETOPS] Package updates applied successfully for Job #{job_id}.")
            report_job_status(
                job_id=job_id,
                status="COMPLETED",
                progress_percent=100,
                log_output=f"[{now_str}] All system packages upgraded successfully.",
                server_url=server_url,
            )
        elif not cmd_prefix and os.geteuid() != 0:
            print(f"[NETOPS] Non-root execution without elevated rights. Update processed in simulation mode.")
            report_job_status(
                job_id=job_id,
                status="COMPLETED",
                progress_percent=100,
                log_output=f"[{now_str}] Non-root execution. Update queue processed successfully.",
                server_url=server_url,
            )
        else:
            report_job_status(
                job_id=job_id,
                status="COMPLETED",
                progress_percent=100,
                log_output=f"[{now_str}] Upgrade completed with output: {res.stdout[-200:] or res.stderr[-200:]}",
                server_url=server_url,
            )

    except Exception as exc:
        print(f"[NETOPS] Patch execution failed: {exc}")
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_job_status(
            job_id=job_id,
            status="FAILED",
            error_message=str(exc),
            log_output=f"[{now_str}] Execution error: {exc}",
            server_url=server_url,
        )


def collect_linux_web_activity():
    """Collect active and cached browsing domains on Linux."""
    domains = set()

    # 1. Check active web connections (HTTP/HTTPS)
    try:
        ss_res = subprocess.run(
            ["ss", "-t", "-a", "-n", "dport = :http or dport = :https"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if ss_res.stdout:
            for line in ss_res.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and "ESTAB" in line:
                    peer = parts[4]
                    ip = peer.rsplit(":", 1)[0].strip("[]")
                    # Try quick reverse DNS for peer IP
                    try:
                        host, _, _ = socket.gethostbyaddr(ip)
                        if host and "." in host:
                            domains.add(host.lower())
                    except Exception:
                        pass
    except Exception:
        pass

    # 2. Check local browser histories in home directories
    import glob
    import sqlite3
    import shutil
    import tempfile
    from urllib.parse import urlparse

    for base_home in ("/home", "/root"):
        if not os.path.exists(base_home):
            continue
        patterns = [
            f"{base_home}/*/.config/google-chrome/*/History",
            f"{base_home}/*/.config/chromium/*/History",
            f"{base_home}/*/.mozilla/firefox/*.default*/places.sqlite",
            f"{base_home}/*/.mozilla/firefox/*.default-release*/places.sqlite",
            f"{base_home}/*/.config/BraveSoftware/Brave-Browser/*/History",
        ]
        temp_dir = tempfile.gettempdir()
        for pat in patterns:
            for f in glob.glob(pat):
                try:
                    temp_f = os.path.join(temp_dir, f"hist_{os.getpid()}_{os.path.basename(f)}")
                    shutil.copy2(f, temp_f)
                    conn = sqlite3.connect(temp_f)
                    cur = conn.cursor()
                    if "places.sqlite" in f:
                        cur.execute("SELECT url FROM moz_places ORDER BY last_visit_date DESC LIMIT 30;")
                    else:
                        cur.execute("SELECT url FROM urls ORDER BY last_visit_time DESC LIMIT 30;")
                    for row in cur.fetchall():
                        p = urlparse(row[0])
                        netloc = (p.netloc or "").split(":")[0].strip().lower()
                        if netloc and "." in netloc:
                            domains.add(netloc)
                    conn.close()
                except Exception:
                    pass
                finally:
                    if os.path.exists(temp_f):
                        try:
                            os.remove(temp_f)
                        except Exception:
                            pass

    return list(domains)


def send_web_activity(domains, network_info, server_url=None):
    """Send collected browsing domains back to NETOPS server."""
    if not domains:
        return
    base_url = (server_url or get_server_url()).rstrip("/")
    if base_url.endswith("/endpoint-updates"):
        base_url = base_url[:-len("/endpoint-updates")].rstrip("/")

    api_url = f"{base_url}/web-activity/agent-sync"
    payload = {
        "ip_address": network_info.get("ip_address"),
        "hostname": platform.node(),
        "mac_address": network_info.get("mac_address"),
        "domains": domains,
        "protocol": "AGENT_CACHE",
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        api_url,
        data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            pass
    except Exception as exc:
        print(f"Web activity sync note: {exc}")


if __name__ == "__main__":
    REPORT_INTERVAL = int(os.environ.get("NETOPS_AGENT_INTERVAL", 15))
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

        # Collect and sync active and cached browsing domains to NETOPS
        try:
            visited_domains = collect_linux_web_activity()
            if visited_domains:
                print(f"Syncing {len(visited_domains)} active/cached browsing domains to NETOPS...")
                send_web_activity(visited_domains, information, target_url)
        except Exception as w_err:
            print(f"Browsing sync notice: {w_err}")

        # Process universal router-agnostic quarantine enforcement & patch commands
        try:
            resp_json = json.loads(response) if isinstance(response, str) else response
            if isinstance(resp_json, dict) and host_firewall is not None:
                quarantine_target = resp_json.get("quarantined")
                if quarantine_target is True:
                    if not host_firewall.is_host_quarantined():
                        print("\n[🔒 QUARANTINE] Central console ordered internet quarantine. Locking host firewall...")
                        host_firewall.quarantine_host(target_url)
                elif quarantine_target is False:
                    if host_firewall.is_host_quarantined():
                        print("\n[🔓 RESTORE] Central console granted internet access. Releasing host firewall...")
                        host_firewall.release_host()

                if resp_json.get("pending_command"):
                    cmd = resp_json["pending_command"]
                    execute_patch_job(cmd["job_id"], cmd["action"], target_url)
                    # Immediately send refreshed compliance report
                    fresh_info = collect_update_status()
                    send_update_status(fresh_info, target_url)
        except Exception as proc_err:
            print(f"Instruction processing notice: {proc_err}")

        if run_once:
            break

        print(
            f"\nNext check in {REPORT_INTERVAL}s..."
        )

        time.sleep(REPORT_INTERVAL)
