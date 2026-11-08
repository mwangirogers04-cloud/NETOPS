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
import sys
import time
import urllib.error
import urllib.request

# Ensure NETOPS root is on sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.app.services.discovery import (
    classify_device,
    detect_local_subnets,
    discover_devices,
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


def sync_to_cloud(server_url: str, devices: list, token: str | None = None) -> bool:
    """Send live discovered devices to NETOPS cloud endpoint."""
    endpoint = f"{server_url.rstrip('/')}/discovery/agent-sync"
    payload = {
        "network": "192.168.0.0/24",
        "interface": "all",
        "devices": devices,
    }
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "NETOPS-Probe/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(endpoint, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode())
            logger.info(
                f"[✓] Synced {len(devices)} device(s) to cloud: "
                f"saved={body.get('devices_saved')}"
            )
            return True
    except urllib.error.HTTPError as err:
        logger.error(f"[!] Cloud sync HTTP {err.code}: {err.read().decode()}")
        return False
    except Exception as exc:
        logger.error(f"[!] Cloud sync failed: {exc}")
        return False


def run_sync_loop(server_url: str, interval: int = 15, token: str | None = None):
    """Main continuous daemon loop."""
    logger.info(f"Starting NETOPS Cloud Sync Daemon targeting {server_url} (interval={interval}s)")
    while True:
        try:
            devices = sweep_local_interfaces()
            if devices:
                sync_to_cloud(server_url, devices, token)
            else:
                logger.info("Sweep returned 0 devices; skipping sync.")
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
        type=int,
        default=int(os.environ.get("NETOPS_SYNC_INTERVAL", "20")),
        help="Sync interval in seconds (default: 20)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("NETOPS_AUTH_TOKEN"),
        help="Optional JWT token",
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
        sync_to_cloud(args.server, devs, args.token)
    else:
        run_sync_loop(args.server, interval=args.interval, token=args.token)


if __name__ == "__main__":
    main()
