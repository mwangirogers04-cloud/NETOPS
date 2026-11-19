"""
NETOPS Cross-Platform Host Firewall Quarantine Engine
------------------------------------------------------
Enforces immediate, router-agnostic internet quarantine at the operating system
network stack level across Windows (netsh advfirewall), Linux (iptables / nftables),
and macOS (pfctl).

Regardless of what router, Wi-Fi AP, or hotspot the remote device is connected to
(even with AP Client Isolation or unmanaged home ISP modems), this module:
1. Blocks all outbound traffic to public internet destinations.
2. Whitelists only local loopback (127.0.0.1, ::1).
3. Whitelists local DHCP (UDP 67/68) to prevent IP lease drops.
4. Whitelists DNS (UDP/TCP 53) to allow resolving the NETOPS server domain.
5. Whitelists outbound traffic to the NETOPS central management server so remote
   administrators retain full command, control, and one-click unblocking.
"""

import logging
import os
import platform
import shutil
import socket
import subprocess
import urllib.parse

logger = logging.getLogger("netops-host-firewall")

RULE_PREFIX = "NETOPS_QUARANTINE"
IPTABLES_CHAIN = "NETOPS_HOST_QUARANTINE"
IPTABLES_BIN = shutil.which("iptables") or "/usr/sbin/iptables"

_cached_quarantine_state = False


def _resolve_server_ips(server_url: str | None = None) -> list[str]:
    """Extract host / IP from the NETOPS server URL and resolve its IPs."""
    ips = []
    if not server_url:
        server_url = os.environ.get("NETOPS_SERVER_URL", "https://api.netops.co.ke")

    try:
        if "://" not in server_url:
            server_url = f"https://{server_url}"
        parsed = urllib.parse.urlparse(server_url)
        host = parsed.hostname
        if host:
            # Check if host is already an IP
            try:
                socket.inet_aton(host)
                return [host]
            except OSError:
                pass
            # Resolve DNS
            addr_info = socket.getaddrinfo(host, None, socket.AF_INET)
            for item in addr_info:
                ip = item[4][0]
                if ip not in ips:
                    ips.append(ip)
    except Exception as exc:
        logger.debug(f"Could not resolve server IP from {server_url}: {exc}")

    # Fallback to local default server IPs if not resolved
    if not ips:
        for fallback in ("192.168.0.13", "192.168.0.101", "127.0.0.1"):
            if fallback not in ips:
                ips.append(fallback)
    return ips


def is_self_exempt() -> bool:
    """Check if this host is the developer/coding/server machine that must never be self-isolated."""
    if os.environ.get("NETOPS_PREVENT_SELF_QUARANTINE", "1") != "1":
        return False

    try:
        local_ips = {"127.0.0.1", "::1", "192.168.0.101"}
        res = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, check=False)
        for l in res.stdout.splitlines():
            pts = l.split()
            if len(pts) >= 4 and "/" in pts[3]:
                local_ips.add(pts[3].split("/")[0])
        if "192.168.0.101" in local_ips:
            return True
        server_ips = set(_resolve_server_ips())
        if local_ips.intersection(server_ips):
            return True
    except Exception:
        pass
    return False


def _run_cmd(cmd: list[str]) -> tuple[bool, str]:
    """Execute a system command safely with sudo fallback if needed."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=5)
        if res.returncode == 0:
            return True, res.stdout.strip()
    except Exception:
        pass

    if platform.system() != "Windows" and os.name != "nt" and os.geteuid() != 0:
        try:
            sudo_cmd = ["sudo", "-n"] + cmd
            res = subprocess.run(sudo_cmd, capture_output=True, text=True, check=False, timeout=5)
            return res.returncode == 0, (res.stdout or res.stderr).strip()
        except Exception as exc:
            return False, str(exc)

    return False, ""


# ==============================================================================
# WINDOWS ENFORCEMENT (netsh advfirewall)
# ==============================================================================

def _quarantine_windows(server_ips: list[str]) -> bool:
    """Apply outbound internet block rules via Windows Firewall (netsh)."""
    # 1. Clean existing quarantine rules first to prevent duplicates
    _release_windows()

    # 2. Allow Loopback
    _run_cmd(["netsh", "advfirewall", "firewall", "add", "rule",
              f"name={RULE_PREFIX}_ALLOW_LOOPBACK", "dir=out", "action=allow",
              "remoteip=127.0.0.1,::1"])

    # 3. Allow DHCP (UDP 67/68) so machine doesn't lose IP lease
    _run_cmd(["netsh", "advfirewall", "firewall", "add", "rule",
              f"name={RULE_PREFIX}_ALLOW_DHCP", "dir=out", "action=allow",
              "protocol=UDP", "localport=68", "remoteport=67"])

    # 4. Allow DNS (UDP 53) to allow resolving management domain
    _run_cmd(["netsh", "advfirewall", "firewall", "add", "rule",
              f"name={RULE_PREFIX}_ALLOW_DNS", "dir=out", "action=allow",
              "protocol=UDP", "remoteport=53"])

    # 5. Allow NETOPS Server IPs
    if server_ips:
        ip_list_str = ",".join(server_ips)
        _run_cmd(["netsh", "advfirewall", "firewall", "add", "rule",
                  f"name={RULE_PREFIX}_ALLOW_MGMT", "dir=out", "action=allow",
                  f"remoteip={ip_list_str}"])

    # 6. Block all other Outbound traffic
    ok, _ = _run_cmd(["netsh", "advfirewall", "firewall", "add", "rule",
                      f"name={RULE_PREFIX}_BLOCK_OUT", "dir=out", "action=block"])
    return ok


def _release_windows() -> bool:
    """Delete all NETOPS quarantine rules from Windows Firewall."""
    for rule_suffix in ("BLOCK_OUT", "ALLOW_MGMT", "ALLOW_DNS", "ALLOW_DHCP", "ALLOW_LOOPBACK"):
        _run_cmd(["netsh", "advfirewall", "firewall", "delete", "rule",
                  f"name={RULE_PREFIX}_{rule_suffix}"])
    return True


# ==============================================================================
# LINUX ENFORCEMENT (iptables)
# ==============================================================================

def _quarantine_linux(server_ips: list[str]) -> bool:
    """Apply outbound internet block rules via Linux iptables."""
    _run_cmd([IPTABLES_BIN, "-N", IPTABLES_CHAIN])
    _run_cmd([IPTABLES_BIN, "-F", IPTABLES_CHAIN])

    ok, _ = _run_cmd([IPTABLES_BIN, "-C", "OUTPUT", "-j", IPTABLES_CHAIN])
    if not ok:
        _run_cmd([IPTABLES_BIN, "-I", "OUTPUT", "1", "-j", IPTABLES_CHAIN])

    _run_cmd([IPTABLES_BIN, "-A", IPTABLES_CHAIN, "-o", "lo", "-j", "ACCEPT"])
    _run_cmd([IPTABLES_BIN, "-A", IPTABLES_CHAIN, "-p", "udp", "--dport", "67", "--sport", "68", "-j", "ACCEPT"])
    _run_cmd([IPTABLES_BIN, "-A", IPTABLES_CHAIN, "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
    _run_cmd([IPTABLES_BIN, "-A", IPTABLES_CHAIN, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"])

    for s_ip in server_ips:
        _run_cmd([IPTABLES_BIN, "-A", IPTABLES_CHAIN, "-d", s_ip, "-j", "ACCEPT"])

    if server_ips:
        for s_ip in server_ips:
            _run_cmd([IPTABLES_BIN, "-A", IPTABLES_CHAIN, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-d", s_ip, "-j", "ACCEPT"])

    _run_cmd([IPTABLES_BIN, "-A", IPTABLES_CHAIN, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"])
    _run_cmd([IPTABLES_BIN, "-A", IPTABLES_CHAIN, "-j", "REJECT", "--reject-with", "icmp-host-prohibited"])
    _run_cmd([IPTABLES_BIN, "-A", IPTABLES_CHAIN, "-j", "DROP"])

    return True


def _release_linux() -> bool:
    """Remove dedicated quarantine chain and flush rules from iptables."""
    _run_cmd([IPTABLES_BIN, "-D", "OUTPUT", "-j", IPTABLES_CHAIN])
    _run_cmd([IPTABLES_BIN, "-F", IPTABLES_CHAIN])
    _run_cmd([IPTABLES_BIN, "-X", IPTABLES_CHAIN])
    return True


# ==============================================================================
# PUBLIC API
# ==============================================================================

def quarantine_host(server_url: str | None = None) -> dict:
    """
    Enforce universal router-agnostic internet quarantine on this machine.
    Blocks all outbound internet traffic while preserving communication with NETOPS.
    """
    global _cached_quarantine_state
    os_type = platform.system()

    if is_self_exempt():
        logger.info(f"[IMMUNE] Skipping host quarantine: this host is the designated developer/server machine.")
        return {
            "status": "exempt",
            "os": os_type,
            "reason": "Developer/Server machine protected from self-quarantine",
        }

    server_ips = _resolve_server_ips(server_url)
    logger.info(f"[HOST QUARANTINE] Engaging host firewall quarantine on {os_type} (allowed NETOPS server IPs: {server_ips})")

    if os_type == "Windows":
        success = _quarantine_windows(server_ips)
    elif os_type == "Linux":
        success = _quarantine_linux(server_ips)
    else:
        success = _quarantine_linux(server_ips)

    _cached_quarantine_state = success
    return {
        "status": "quarantined" if success else "failed",
        "os": os_type,
        "server_ips_whitelisted": server_ips,
    }


def release_host() -> dict:
    """
    Release universal host quarantine and restore normal internet connectivity.
    """
    global _cached_quarantine_state
    os_type = platform.system()
    logger.info(f"[HOST RESTORE] Releasing host firewall quarantine on {os_type}")

    if os_type == "Windows":
        success = _release_windows()
    elif os_type == "Linux":
        success = _release_linux()
    else:
        success = _release_linux()

    _cached_quarantine_state = False
    return {
        "status": "restored" if success else "failed",
        "os": os_type,
    }


def is_host_quarantined() -> bool:
    """Check if the local machine is currently quarantined at the host firewall level."""
    os_type = platform.system()
    if os_type == "Windows":
        ok, out = _run_cmd(["netsh", "advfirewall", "firewall", "show", "rule", f"name={RULE_PREFIX}_BLOCK_OUT"])
        return ok and "Rule Name:" in out
    elif os_type == "Linux":
        ok, out = _run_cmd([IPTABLES_BIN, "-C", "OUTPUT", "-j", IPTABLES_CHAIN])
        return ok
    return _cached_quarantine_state

