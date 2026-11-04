#!/usr/bin/env python3
"""
NETOPS Remote LAN Scanner Probe
--------------------------------
Cross-platform client scanner that discovers devices connected to the local
physical network (home, office, or remote branch) and securely syncs them to
your cloud-hosted NETOPS dashboard.

Usage:
    python netops_probe.py --server https://your-netops-domain.com --token YOUR_JWT_TOKEN
    python netops_probe.py --interactive
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import urllib.request
import urllib.error


def get_local_ip_and_subnet():
    """Detect local IP and approximate subnet range (defaults to /24)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to a public DNS IP (doesn't send packets) to get default outgoing interface IP
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()

    if local_ip.startswith("127."):
        return "127.0.0.1", "127.0.0.1/32"

    parts = local_ip.split(".")
    subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return local_ip, subnet


def get_arp_table():
    """Read local OS ARP / Neighbour cache."""
    mac_table = {}
    system = platform.system().lower()

    try:
        if system == "windows":
            output = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    mac = parts[1].replace("-", ":").upper()
                    if re.match(r"^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$", mac):
                        mac_table[ip] = mac
        else:
            # Linux / macOS
            try:
                output = subprocess.check_output(["ip", "neigh"], text=True, stderr=subprocess.DEVNULL)
                for line in output.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and "lladdr" in parts:
                        idx = parts.index("lladdr")
                        ip = parts[0]
                        mac = parts[idx + 1].upper()
                        mac_table[ip] = mac
            except Exception:
                output = subprocess.check_output(["arp", "-n"], text=True, stderr=subprocess.DEVNULL)
                for line in output.splitlines():
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0].strip("()")
                        mac = parts[2].upper()
                        if re.match(r"^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$", mac):
                            mac_table[ip] = mac
    except Exception:
        pass

    return mac_table


def ping_host(ip):
    """Ping a single IP address with short timeout."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "500", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.5)
        return ip if res.returncode == 0 else None
    except Exception:
        return None


def resolve_hostname(ip):
    """Attempt reverse DNS or NetBIOS resolution."""
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name
    except Exception:
        pass
    return f"Host-{ip.replace('.', '-')}"


def scan_local_subnet(network_cidr, max_workers=60):
    """Scan local subnet and return discovered devices with MAC, IP, and hostname."""
    print(f"[*] Scanning subnet: {network_cidr} ...")
    net = ipaddress.ip_network(network_cidr, strict=False)
    hosts = [str(ip) for ip in net.hosts()][:254]

    live_ips = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in hosts}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                live_ips.add(res)

    print(f"[+] Found {len(live_ips)} responsive IP address(es). Reading ARP cache...")
    arp_cache = get_arp_table()

    devices = []
    for ip in live_ips:
        mac = arp_cache.get(ip)
        if not mac:
            # Fallback pseudo-MAC if ping answered but not in ARP (e.g. gateway/host)
            hex_ip = "".join(f"{int(o):02X}" for o in ip.split("."))
            mac = f"02:00:{hex_ip[:2]}:{hex_ip[2:4]}:{hex_ip[4:6]}:{hex_ip[6:]}"

        hostname = resolve_hostname(ip)
        devices.append({
            "ip_address": ip,
            "mac_address": mac,
            "hostname": hostname,
            "vendor": "Local Network Device",
            "device_type": "computer" if not ip.endswith(".1") else "router",
        })

    return devices


def login_for_token(server_url, username, password):
    """Authenticate with NETOPS credentials and obtain JWT access token."""
    endpoint = f"{server_url.rstrip('/')}/auth/login"
    payload = json.dumps({"username": username, "password": password}).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            return data.get("access_token")
    except Exception as e:
        print(f"[!] Authentication failed on {server_url}: {e}")
        return None


def sync_to_netops(server_url, token, network, devices):
    """Upload discovered devices to NETOPS cloud endpoint."""
    endpoint = f"{server_url.rstrip('/')}/discovery/agent-sync"
    payload = {
        "network": network,
        "interface": "client-probe",
        "devices": devices,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "NETOPS-Probe/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            res_body = json.loads(resp.read().decode())
            print(f"[✓] Synchronization successful! Saved {res_body.get('devices_saved', len(devices))} devices under your account.")
            return True
    except urllib.error.HTTPError as e:
        print(f"[!] Server returned error: HTTP {e.code} - {e.read().decode()}")
        return False
    except Exception as e:
        print(f"[!] Failed to connect to NETOPS server: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="NETOPS Remote Physical LAN Scanner Probe")
    parser.add_argument("--server", default="https://api.netops.co.ke", help="NETOPS backend URL (defaults to https://api.netops.co.ke)")
    parser.add_argument("--token", help="Your NETOPS user authentication JWT token")
    parser.add_argument("--username", help="Your NETOPS account username")
    parser.add_argument("--password", help="Your NETOPS account password")
    parser.add_argument("--network", help="Subnet to scan (defaults to auto-detected local LAN e.g. 192.168.1.0/24)")
    parser.add_argument("--interactive", action="store_true", help="Prompt interactively for credentials and network")

    args = parser.parse_args()

    server_url = (args.server or "https://api.netops.co.ke").strip().rstrip("/")
    token = args.token
    network = args.network

    if not token and (args.username and args.password):
        print(f"[*] Authenticating with {server_url} as {args.username}...")
        token = login_for_token(server_url, args.username, args.password)
        if not token:
            print("[!] Exiting due to authentication failure.")
            sys.exit(1)

    if not token:
        print("=" * 64)
        print("  NETOPS Remote Physical LAN Scanner")
        print(f"  Target Cloud Server: {server_url}")
        print("=" * 64)
        try:
            uname = input("Username / Email: ").strip()
            import getpass
            pwd = getpass.getpass("Password: ").strip()
            token = login_for_token(server_url, uname, pwd)
            if not token:
                print("[!] Authentication failed. Please verify your credentials.")
                sys.exit(1)
            print("[✓] Authenticated successfully!")
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Canceled.")
            sys.exit(0)

    local_ip, auto_subnet = get_local_ip_and_subnet()
    if not network:
        network = auto_subnet
        print(f"[*] Auto-detected local IP: {local_ip} on subnet {network}")

    devices = scan_local_subnet(network)
    print(f"[*] Discovered {len(devices)} device(s) on local physical network.")
    for d in devices:
        print(f"    - IP: {d['ip_address']:16} MAC: {d['mac_address']:17} Name: {d['hostname']}")

    print(f"[*] Syncing {len(devices)} device(s) to {server_url} ...")
    sync_to_netops(server_url, token, network, devices)
    print("=" * 64)
    print("  All done! Refresh your dashboard at https://www.netops.co.ke")
    print("=" * 64)


if __name__ == "__main__":
    main()
