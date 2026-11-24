#!/usr/bin/env python3
"""
NETOPS Local Network Cloud Sync Daemon
---------------------------------------
Continuously monitors local physical network interfaces (wlan0, eth0)
on this machine and pushes live active devices to the cloud-hosted
NETOPS management console (https://api.netops.co.ke).

This ensures that remote users logging into https://www.netops.co.ke
always see the real-time online status and inventory of physical network devices.
"""

import argparse
import json
import logging
import os
import platform
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

# Ensure NETOPS root is on sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

env_file = os.path.join(PROJECT_ROOT, ".env")
if os.path.exists(env_file):
    try:
        from dotenv import load_dotenv
        load_dotenv(env_file)
    except Exception:
        pass
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from backend.app.services.discovery import (
    classify_device,
    detect_local_subnets,
    discover_devices,
)
from backend.app.services.l2_quarantine import (
    quarantine_device_l2,
    restore_device_l2,
    is_protected,
    is_target_quarantined,
    is_valid_quarantine_ip,
)
try:
    from . import host_firewall
except ImportError:
    try:
        import host_firewall
    except ImportError:
        host_firewall = None
from backend.app.services.sophos_enforcement import (
    is_sophos_configured,
    sophos_block_device,
    sophos_allow_device,
)
from backend.app.services.router.manager import get_active_router_driver

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("netops-cloud-sync")


def get_active_interfaces():
    """Detect available physical LAN / WLAN interfaces on this host."""
    interfaces = []
    for iface in ("wlan0", "eth0", "lan0", "enp0s3"):
        if os.path.exists(f"/sys/class/net/{iface}"):
            interfaces.append(iface)
    return interfaces or ["wlan0", "eth0"]


def sweep_local_interfaces():
    """Discover active devices on all local interfaces."""
    subnets_info = detect_local_subnets()
    all_devices = []
    seen_macs = set()

    for iface in get_active_interfaces():
        net = "192.168.0.0/24"
        for if_info in subnets_info.get("interfaces", []):
            if if_info.get("interface") == iface and if_info.get("network"):
                net = if_info["network"]
                break

        try:
            devs = discover_devices(net, interface=iface)
            for d in devs:
                mac = (d.get("mac_address") or "").upper()
                if not mac or mac in seen_macs:
                    continue
                seen_macs.add(mac)
                d["network_interface"] = iface
                d["interface"] = iface

                # Classify if unknown
                if not d.get("device_type") or d.get("device_type") == "unknown":
                    d["device_type"] = classify_device(
                        hostname=d.get("hostname"),
                        vendor=d.get("vendor"),
                        mac_address=mac,
                    )

                # Assign friendly phone hostname if detected as phone
                if d.get("device_type") == "phone":
                    ip = d.get("ip_address") or ""
                    clean_ip = ip.replace(".", "-") if ip else mac[-8:].replace(":", "-")
                    if not d.get("hostname") or d["hostname"].startswith("LAN-HOST-"):
                        d["hostname"] = f"Phone-{clean_ip}"

                all_devices.append(d)
        except Exception as exc:
            logger.warning(f"Error sweeping {iface}: {exc}")

    return all_devices


def _get_quick_kernel_devices() -> list[dict]:
    """Fast extraction of active LAN devices from kernel neighbor table and ARP cache (< 5ms)."""
    devices = []
    seen = set()
    # 1. ip neigh
    try:
        res = subprocess.run(
            ["ip", "-4", "neigh", "show"],
            capture_output=True,
            text=True,
            check=False,
            timeout=1,
        )
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and "lladdr" in parts and "dev" in parts:
                state = parts[-1].upper() if len(parts) > parts.index("lladdr") + 1 else ""
                if state in ("FAILED", "INCOMPLETE"):
                    continue
                ip = parts[0]
                mac = parts[parts.index("lladdr") + 1].upper()
                iface = parts[parts.index("dev") + 1]
                if mac and len(mac) == 17 and mac not in seen and is_valid_quarantine_ip(ip):
                    seen.add(mac)
                    devices.append({
                        "ip_address": ip,
                        "mac_address": mac,
                        "hostname": f"HOST-{ip.replace('.', '-')}",
                        "network_interface": iface,
                        "interface": iface,
                        "status": "online",
                    })
    except Exception:
        pass

    # 2. /proc/net/arp fallback
    if not devices and os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", "r", encoding="utf-8") as f:
                lines = f.readlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 6:
                    ip, mac, iface = parts[0], parts[3].upper(), parts[5]
                    if len(mac) == 17 and mac != "00:00:00:00:00:00" and mac not in seen and is_valid_quarantine_ip(ip):
                        seen.add(mac)
                        devices.append({
                            "ip_address": ip,
                            "mac_address": mac,
                            "hostname": f"HOST-{ip.replace('.', '-')}",
                            "network_interface": iface,
                            "interface": iface,
                            "status": "online",
                        })
        except Exception:
            pass

    return devices


_cached_devices: list[dict] = []
_devices_lock = threading.Lock()
_locally_quarantined_ips: set[str] = set()
_synced_router_quarantined_ips: set[str] = set()
_synced_router_allowed_ips: set[str] = set()
_enforcement_initialized: bool = False
_handled_reboot_job_ids: set[int] = set()


def _get_local_db_devices() -> dict[str, dict]:
    """Retrieve device approval and authorization status from local database."""
    local_devs = {}
    try:
        from backend.app.database import SessionLocal
        from backend.app.models.device import Device
        from sqlalchemy import select
        with SessionLocal() as db:
            devs = db.scalars(select(Device)).all()
            for d in devs:
                mac = (d.mac_address or "").replace(":", "").replace("-", "").upper()
                if mac:
                    local_devs[mac] = {
                        "id": d.id,
                        "ip_address": d.ip_address,
                        "mac_address": d.mac_address,
                        "approval_status": d.approval_status,
                        "internet_access_authorized": d.internet_access_authorized,
                        "enforcement_status": d.enforcement_status,
                        "vlan_id": d.vlan_id,
                    }
    except Exception as exc:
        logger.debug("Local DB query note in cloud_sync: %s", exc)
    return local_devs


def _report_job_status_to_cloud(
    server_url: str,
    job_id: int,
    status: str,
    progress_percent: int = 100,
    log_output: str | None = None,
    error_message: str | None = None,
    token: str | None = None,
):
    """Callback to report job execution progress or completion to cloud console."""
    endpoint = f"{server_url.rstrip('/')}/endpoint-updates/jobs/{job_id}/status"
    payload = {
        "status": status,
        "progress_percent": progress_percent,
        "log_output": log_output,
        "error_message": error_message,
    }
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 NETOPS/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(endpoint, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=12) as resp:
            pass
    except Exception as exc:
        logger.warning(f"[RebootWorker] Could not report job #{job_id} status to cloud: {exc}")


def _handle_reboot_commands(server_url: str, reboot_commands: list[dict], token: str | None = None):
    """Execute pending reboot jobs for on-prem endpoints or local host."""
    global _handled_reboot_job_ids
    for cmd in reboot_commands:
        job_id = cmd.get("job_id")
        if not job_id or job_id in _handled_reboot_job_ids:
            continue
        _handled_reboot_job_ids.add(job_id)

        target_ip = (cmd.get("ip_address") or "").strip()
        target_mac = (cmd.get("mac_address") or "").replace(":", "").replace("-", "").upper()
        target_host = (cmd.get("hostname") or "endpoint").strip()
        now_str = time.strftime("%Y-%m-%d %H:%M:%S")

        # Discover all IPs and MACs belonging to this host machine running the agent
        local_ips = {"127.0.0.1", "localhost"}
        try:
            res = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, check=False)
            for l in res.stdout.splitlines():
                pts = l.split()
                if len(pts) >= 4 and "/" in pts[3]:
                    local_ips.add(pts[3].split("/")[0])
        except Exception:
            pass

        local_macs = set()
        try:
            res = subprocess.run(["ip", "link", "show"], capture_output=True, text=True, check=False)
            for l in res.stdout.splitlines():
                pts = l.strip().split()
                if len(pts) >= 2 and pts[0] == "link/ether":
                    local_macs.add(pts[1].replace(":", "").replace("-", "").upper())
        except Exception:
            pass

        local_hostnames = {
            socket.gethostname().lower(),
            platform.node().lower(),
            "kali",
            "localhost",
        }

        is_this_host = (
            (target_ip and target_ip in local_ips)
            or (target_mac and target_mac in local_macs)
            or (target_host and target_host.lower() in local_hostnames)
        )

        if is_this_host:
            logger.info(f"[🔄 REBOOT] Received restart command for this host ({target_host} / {target_ip}). Executing system reboot...")
            _report_job_status_to_cloud(
                server_url=server_url,
                job_id=job_id,
                status="COMPLETED",
                progress_percent=100,
                log_output=(
                    f"[{now_str}] Local system restart instruction acknowledged by agent host ({target_host} / {target_ip}).\n"
                    f"[{now_str}] Dispatching local system command: shutdown -r +1 'NETOPS System Update Reboot'"
                ),
                token=token,
            )
            try:
                subprocess.Popen(["shutdown", "-r", "+1", "NETOPS System Update Reboot"])
            except Exception as e:
                logger.error(f"[!] Local reboot failed: {e}")
        else:
            logger.info(f"[🔄 REBOOT] Attempting remote LAN reboot for {target_host} ({target_ip})...")
            reboot_ok = False
            diag = None
            if target_ip:
                try:
                    res = subprocess.run(
                        ["net", "rpc", "shutdown", "-I", target_ip, "-U", "%", "-t", "5", "-f"],
                        capture_output=True,
                        text=True,
                        timeout=8,
                        check=False,
                    )
                    if res.returncode == 0:
                        reboot_ok = True
                    else:
                        diag = res.stderr.strip() or res.stdout.strip()
                except subprocess.TimeoutExpired:
                    diag = "Connection timed out (Port 445/135 filtered by Windows Defender Firewall)"
                except Exception as ex:
                    diag = str(ex)

            if reboot_ok:
                logger.info(f"[✓] Remote reboot signal delivered to {target_host} ({target_ip}).")
                _report_job_status_to_cloud(
                    server_url=server_url,
                    job_id=job_id,
                    status="COMPLETED",
                    progress_percent=100,
                    log_output=f"[{now_str}] Remote endpoint {target_host} ({target_ip}) accepted reboot signal via Windows RPC.",
                    token=token,
                )
            else:
                err_msg = diag or "Endpoint rejected remote RPC shutdown"
                guidance = (
                    f"Remote endpoint {target_host} ({target_ip}) rejected network shutdown: {err_msg}.\n"
                    f"To reboot remote Windows endpoints over the network:\n"
                    f"  1. Run the NETOPS Windows Agent on that PC (python agent/windows/update_monitor.py), OR\n"
                    f"  2. Configure Administrator credentials and allow remote RPC in Windows Defender Firewall."
                )
                logger.warning(f"[!] Remote reboot failed for {target_ip}: {err_msg}")
                _report_job_status_to_cloud(
                    server_url=server_url,
                    job_id=job_id,
                    status="FAILED",
                    progress_percent=100,
                    error_message=err_msg,
                    log_output=f"[{now_str}] {guidance}",
                    token=token,
                )


def _background_discovery_sweep(interval: float = 45.0):
    """Background worker that executes deep subnet discovery without blocking enforcement polling."""
    global _cached_devices
    while True:
        try:
            devs = sweep_local_interfaces()
            if devs:
                with _devices_lock:
                    _cached_devices = devs
                logger.info(f"[Sweeper] Deep interface sweep refreshed {len(devs)} active device(s).")
        except Exception as exc:
            logger.warning(f"[Sweeper] Background sweep note: {exc}")

        time.sleep(interval)


def sync_to_cloud(server_url: str, devices: list, token: str | None = None, network_name: str = "Home Network") -> bool:
    """Send live discovered devices to NETOPS cloud endpoint and enforce Layer 2 states rapidly."""
    global _locally_quarantined_ips, _enforcement_initialized
    endpoint = f"{server_url.rstrip('/')}/discovery/agent-sync"
    payload = {
        "network": "192.168.0.0/24",
        "interface": "all",
        "network_name": network_name,
        "devices": devices,
    }
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 NETOPS/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(endpoint, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            body = json.loads(resp.read().decode())
            quarantined = body.get("quarantined_devices", [])
            allowed = body.get("allowed_devices", [])

            current_quarantined_map = {
                d["ip_address"]: d
                for d in quarantined
                if d.get("ip_address") and d.get("mac_address") and not is_protected(d.get("ip_address"), d.get("mac_address"))
            }
            current_quarantined_ips = set(current_quarantined_map.keys())
            current_allowed_map = {
                d["ip_address"]: d
                for d in allowed
                if d.get("ip_address") and d.get("mac_address") and d.get("ip_address") not in current_quarantined_ips
            }

            # 0. Universal Host Firewall Enforcement (Router-Agnostic for this machine)
            if host_firewall is not None:
                local_ips = set()
                try:
                    res = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, check=False)
                    for l in res.stdout.splitlines():
                        pts = l.split()
                        if len(pts) >= 4 and "/" in pts[3]:
                            local_ips.add(pts[3].split("/")[0])
                except Exception:
                    pass

                should_quarantine_self = any(lip in current_quarantined_ips for lip in local_ips)
                if should_quarantine_self:
                    if not host_firewall.is_host_quarantined():
                        logger.info("[🔒 HOST QUARANTINE] Central console quarantined this host. Engaging host firewall...")
                        host_firewall.quarantine_host(server_url)
                else:
                    if host_firewall.is_host_quarantined():
                        logger.info("[🔓 HOST RESTORE] Central console allowed this host. Releasing host firewall...")
                        host_firewall.release_host()

            # Reconcile local DB states so locally allowed devices are never re-quarantined
            local_db_devs = _get_local_db_devices()
            locally_allowed_ips = set()
            for ld in local_db_devs.values():
                if ld.get("approval_status") == "approved" and ld.get("internet_access_authorized") is True:
                    if ld.get("ip_address"):
                        locally_allowed_ips.add(ld["ip_address"])

            # 1. Immediate Layer-2 Restoration for allowed devices (unblock + authentic GARP restoration)
            for ip, dev in current_allowed_map.items():
                if ip in current_quarantined_ips and ip not in locally_allowed_ips:
                    continue
                mac = dev.get("mac_address")
                dev_iface = dev.get("network_interface") or dev.get("interface")
                if ip in _locally_quarantined_ips or is_target_quarantined(ip, mac):
                    try:
                        restore_device_l2(ip, mac, burst=15, interface="all")
                        _locally_quarantined_ips.discard(ip)
                        logger.info(f"[⚡ RESTORED] Rapid ARP unpoisoning & unblocking for {ip} ({mac})")
                    except Exception as r_exc:
                        logger.debug(f"L2 restore call for {ip} note: {r_exc}")

            # 2. Immediate Layer-2 Quarantine for quarantined devices (block + continuous poison)
            for ip, dev in current_quarantined_map.items():
                mac = dev.get("mac_address")
                mac_clean = (mac or "").replace(":", "").replace("-", "").upper()
                if is_protected(ip, mac):
                    continue

                # If device is approved & authorized in local DB, do not re-quarantine it!
                is_local_approved = (
                    ip in locally_allowed_ips
                    or (
                        mac_clean in local_db_devs
                        and local_db_devs[mac_clean].get("approval_status") == "approved"
                        and local_db_devs[mac_clean].get("internet_access_authorized") is True
                    )
                )
                if is_local_approved:
                    if ip in _locally_quarantined_ips or is_target_quarantined(ip, mac):
                        try:
                            restore_device_l2(ip, mac, burst=15, interface="all")
                            _locally_quarantined_ips.discard(ip)
                            logger.info(f"[⚡ LOCAL-ALLOWED] Device {ip} ({mac}) is approved locally; restored L2 access.")
                        except Exception:
                            pass
                    continue

                dev_iface = dev.get("network_interface") or dev.get("interface")
                if ip not in _locally_quarantined_ips or not is_target_quarantined(ip, mac):
                    try:
                        quarantine_device_l2(ip, mac, burst=5, interface=dev_iface)
                        _locally_quarantined_ips.add(ip)
                        logger.info(f"[🔒 QUARANTINED] Rapid L2 ARP poison & blocking enforced for {ip} ({mac})")
                    except Exception as q_exc:
                        logger.debug(f"L2 quarantine call for {ip} note: {q_exc}")

            if not _enforcement_initialized:
                logger.info(
                    f"[✓] Initial cloud sync complete: {len(devices)} device(s) reported | "
                    f"quarantined={len(current_quarantined_map)} | allowed={len(current_allowed_map)}"
                )
                _enforcement_initialized = True

            # 3. Synchronize external hardware firewall (Sophos) & local router asynchronously
            def _sync_hardware_async(q_list, a_list):
                global _synced_router_quarantined_ips, _synced_router_allowed_ips
                # A. Router-level enforcement (Tenda, TP-Link, MikroTik, Universal Engine)
                try:
                    router_drv = get_active_router_driver()
                    for d in q_list:
                        ip_d = d.get("ip_address")
                        mac_d = d.get("mac_address")
                        if ip_d and mac_d and ip_d not in _synced_router_quarantined_ips:
                            try:
                                router_drv.block_device(ip_d, mac_d)
                                _synced_router_quarantined_ips.add(ip_d)
                                _synced_router_allowed_ips.discard(ip_d)
                            except Exception:
                                pass
                    for d in a_list:
                        ip_d = d.get("ip_address")
                        mac_d = d.get("mac_address")
                        if ip_d and mac_d and ip_d not in _synced_router_allowed_ips:
                            try:
                                router_drv.allow_device(ip_d, mac_d)
                                _synced_router_allowed_ips.add(ip_d)
                                _synced_router_quarantined_ips.discard(ip_d)
                            except Exception:
                                pass
                except Exception as r_err:
                    logger.debug("Router sync notice: %s", r_err)

                # B. Firewall enforcement (Sophos)
                if is_sophos_configured():
                    for d in q_list:
                        ip_d = d.get("ip_address")
                        if ip_d:
                            try:
                                sophos_block_device(ip_d)
                            except Exception:
                                pass
                    for d in a_list:
                        ip_d = d.get("ip_address")
                        if ip_d:
                            try:
                                sophos_allow_device(ip_d)
                            except Exception:
                                pass

            threading.Thread(
                target=_sync_hardware_async,
                args=(quarantined, allowed),
                daemon=True,
                name="HardwareSyncWorker",
            ).start()

            # 4. Handle remote & local machine reboot instructions from central console
            reboot_commands = body.get("reboot_commands", [])
            if reboot_commands:
                threading.Thread(
                    target=_handle_reboot_commands,
                    args=(server_url, reboot_commands, token),
                    daemon=True,
                    name="RebootWorker",
                ).start()

            return True
    except urllib.error.HTTPError as err:
        logger.error(f"[!] Cloud sync HTTP {err.code}: {err.read().decode()}")
        return False
    except Exception as exc:
        logger.error(f"[!] Cloud sync failed: {exc}")
        return False


def run_sync_loop(server_url: str, interval: float = 2.0, token: str | None = None, network_name: str = "Home Network"):
    """Main continuous daemon loop with high-frequency enforcement polling and background sweeping."""
    logger.info(f"Starting NETOPS Cloud Sync Daemon targeting {server_url} (site={network_name}, polling={interval}s)")

    # 1. Quick initial neighbor read (< 5ms)
    global _cached_devices
    initial_devs = _get_quick_kernel_devices()
    with _devices_lock:
        _cached_devices = initial_devs

    # 2. Start background interface sweeper thread (deep scanning every 45s)
    sweeper_thread = threading.Thread(
        target=_background_discovery_sweep,
        daemon=True,
        name="NetopsSweeperWorker",
    )
    sweeper_thread.start()

    # 3. Fast high-frequency enforcement sync loop
    while True:
        try:
            # Rapid neighbor table check (< 5ms)
            quick_devs = _get_quick_kernel_devices()
            valid_ips = {d["ip_address"] for d in quick_devs if d.get("ip_address")}
            failed_ips = set()
            try:
                res = subprocess.run(
                    ["ip", "-4", "neigh", "show"],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=1,
                )
                for line in res.stdout.splitlines():
                    pts = line.split()
                    if len(pts) >= 2 and pts[-1].upper() in ("FAILED", "INCOMPLETE"):
                        failed_ips.add(pts[0])
            except Exception:
                pass

            truly_failed_ips = failed_ips - valid_ips

            with _devices_lock:
                mac_map = {}
                for d in _cached_devices:
                    if d.get("mac_address") and d.get("ip_address") not in truly_failed_ips:
                        mac_map[d["mac_address"]] = d
                for qd in quick_devs:
                    mac = qd.get("mac_address")
                    if mac:
                        if mac not in mac_map:
                            mac_map[mac] = qd
                        else:
                            mac_map[mac]["status"] = "online"
                            mac_map[mac]["ip_address"] = qd.get("ip_address") or mac_map[mac].get("ip_address")
                devs_to_send = list(mac_map.values())
                # Enrich with local database approval / authorization states
                local_db_devs = _get_local_db_devices()
                for dev in devs_to_send:
                    m_clean = (dev.get("mac_address") or "").replace(":", "").replace("-", "").upper()
                    if m_clean in local_db_devs:
                        ld = local_db_devs[m_clean]
                        if ld.get("approval_status"):
                            dev["approval_status"] = ld["approval_status"]
                        if ld.get("internet_access_authorized") is not None:
                            dev["internet_access_authorized"] = ld["internet_access_authorized"]
                        if ld.get("enforcement_status"):
                            dev["enforcement_status"] = ld["enforcement_status"]
                        if ld.get("vlan_id") is not None:
                            dev["vlan_id"] = ld["vlan_id"]

            sync_to_cloud(server_url, devs_to_send, token, network_name=network_name)
        except Exception as exc:
            logger.error(f"Unexpected error in sync loop: {exc}")

        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="NETOPS Cloud Network Sync Daemon")
    parser.add_argument(
        "--server",
        default=os.environ.get("NETOPS_SERVER_URL", "https://api.netops.co.ke"),
        help="Target NETOPS API URL (defaults to https://api.netops.co.ke)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=float(os.environ.get("NETOPS_SYNC_INTERVAL", "2.0")),
        help="Enforcement sync interval in seconds (default: 2.0)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("NETOPS_AUTH_TOKEN"),
        help="Optional JWT token",
    )
    parser.add_argument(
        "--network-name",
        default=os.environ.get("NETOPS_NETWORK_NAME", "Home Network"),
        help="Network / site name for this enforcer agent (default: Home Network)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run once and exit immediately",
    )
    args = parser.parse_args()

    if args.once:
        devs = sweep_local_interfaces()
        logger.info(f"Discovered {len(devs)} device(s):")
        for d in devs:
            logger.info(f"  - {d.get('ip_address')} ({d.get('mac_address')}): {d.get('hostname')} [{d.get('network_interface')}]")
        sync_to_cloud(args.server, devs, args.token, network_name=args.network_name)
    else:
        run_sync_loop(args.server, interval=args.interval, token=args.token, network_name=args.network_name)


if __name__ == "__main__":
    main()
