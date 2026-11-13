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
)
from backend.app.services.sophos_enforcement import (
    is_sophos_configured,
    sophos_block_device,
    sophos_allow_device,
)

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
                ip = parts[0]
                mac = parts[parts.index("lladdr") + 1].upper()
                iface = parts[parts.index("dev") + 1]
                if mac and len(mac) == 17 and mac not in seen and ip.startswith("192.168.0."):
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
                    if len(mac) == 17 and mac != "00:00:00:00:00:00" and mac not in seen and ip.startswith("192.168.0."):
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
_enforcement_initialized: bool = False


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

            # 1. Immediate Layer-2 Restoration for allowed devices (unblock + authentic GARP restoration)
            for ip, dev in current_allowed_map.items():
                if ip in current_quarantined_ips:
                    continue
                mac = dev.get("mac_address")
                dev_iface = dev.get("network_interface") or dev.get("interface")
                if ip in _locally_quarantined_ips or is_target_quarantined(ip, mac):
                    try:
                        restore_device_l2(ip, mac, burst=5, interface=dev_iface)
                        _locally_quarantined_ips.discard(ip)
                        logger.info(f"[⚡ RESTORED] Rapid ARP unpoisoning & unblocking for {ip} ({mac})")
                    except Exception as r_exc:
                        logger.debug(f"L2 restore call for {ip} note: {r_exc}")

            # 2. Immediate Layer-2 Quarantine for quarantined devices (block + continuous poison)
            for ip, dev in current_quarantined_map.items():
                mac = dev.get("mac_address")
                if is_protected(ip, mac):
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

            # 3. Synchronize external hardware firewall (Sophos) asynchronously
            def _sync_sophos_async(q_list, a_list):
                if not is_sophos_configured():
                    return
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
                target=_sync_sophos_async,
                args=(quarantined, allowed),
                daemon=True,
                name="SophosSyncWorker",
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
            with _devices_lock:
                devs_to_send = list(_cached_devices)
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
