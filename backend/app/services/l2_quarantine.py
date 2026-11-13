import glob
import logging
import os
import socket
import struct
import subprocess
import threading
import time

logger = logging.getLogger(__name__)

STATIC_PROTECTED_IPS = {
    "127.0.0.1",
    "0.0.0.0",
    "192.168.0.1",    # Wi-Fi Router / Gateway (Tenda)
    "192.168.0.2",    # Cisco Core Switch
    "192.168.0.10",   # Sophos Firewall
    "192.168.0.11",   # MikroTik Router
    "192.168.0.13",   # NETOPS Server eth0 static
}

STATIC_PROTECTED_MACS = {
    "50:0F:F5:98:F0:10",  # Router Gateway
    "7C:5A:1C:A4:0B:10",  # Sophos Firewall
    "2C:C8:1B:EA:E5:E2",  # MikroTik Router
    "B4:B6:86:8A:69:02",  # NETOPS Server eth0
    "D4:6D:6D:E6:A2:67",  # NETOPS Server wlan0
}

_cached_protected_ips: set[str] = set(STATIC_PROTECTED_IPS)
_cached_protected_macs: set[str] = set(STATIC_PROTECTED_MACS)
_last_protected_refresh: float = 0.0


def get_all_protected_ips() -> set[str]:
    """Dynamically discover all local host interface IPs, gateways, and infrastructure IPs."""
    global _cached_protected_ips, _cached_protected_macs, _last_protected_refresh
    now = time.time()
    if now - _last_protected_refresh < 10.0 and _cached_protected_ips:
        return _cached_protected_ips

    ips = set(STATIC_PROTECTED_IPS)
    macs = set(STATIC_PROTECTED_MACS)

    # 1. Local interface MACs from /sys/class/net/*/address
    for iface_path in glob.glob("/sys/class/net/*"):
        addr_file = os.path.join(iface_path, "address")
        if os.path.exists(addr_file):
            try:
                with open(addr_file, "r", encoding="utf-8") as f:
                    m = f.read().strip().upper()
                    if len(m) == 17 and m != "00:00:00:00:00:00":
                        macs.add(m)
            except Exception:
                pass

    # 2. Local interface IPs from `ip -4 -o addr show`
    try:
        res = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"],
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[3].split("/")[0]
                ips.add(ip)
    except Exception:
        pass

    # 3. Default gateway IPs from `ip -4 route show default`
    try:
        res = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )
        for line in res.stdout.splitlines():
            parts = line.split()
            if "via" in parts:
                gw_ip = parts[parts.index("via") + 1]
                ips.add(gw_ip)
    except Exception:
        pass

    _cached_protected_ips = ips
    _cached_protected_macs = macs
    _last_protected_refresh = now
    return _cached_protected_ips


def get_all_protected_macs() -> set[str]:
    """Dynamically discover all local host interface MACs and infrastructure MACs."""
    get_all_protected_ips()
    return _cached_protected_macs


def is_protected(ip_address: str | None, mac_address: str | None = None) -> bool:
    """Return True if an IP or MAC belongs to local server or critical network infrastructure."""
    if not ip_address and not mac_address:
        return False
    protected_ips = get_all_protected_ips()
    protected_macs = get_all_protected_macs()
    if ip_address:
        clean_ip = ip_address.strip()
        if clean_ip in protected_ips or clean_ip.endswith(".1"):
            return True
    if mac_address:
        clean_mac = mac_address.strip().upper()
        if clean_mac in protected_macs:
            return True
    return False


PROTECTED_IPS = STATIC_PROTECTED_IPS

IPTABLES_CHAIN = "NETOPS_L2_QUARANTINE"
_iptables_initialized = False
_currently_blocked_ips: set[str] = set()

# Continuous ARP poisoning registry and worker
_active_quarantine_targets: dict[str, dict] = {}
_quarantine_lock = threading.Lock()
_worker_thread: threading.Thread | None = None
_worker_running: bool = False


def _is_test_env() -> bool:
    return bool(os.environ.get("PYTEST_CURRENT_TEST"))


def _is_cloud_host() -> bool:
    if _is_test_env():
        return False
    return (
        os.environ.get("RENDER") is not None
        or os.environ.get("CLOUD_MODE") == "true"
        or os.environ.get("APP_ENV") == "production"
        or os.environ.get("DYNO") is not None
        or (
            not os.path.exists("/sys/class/net/wlan0")
            and not any(os.path.exists(f"/sys/class/net/{i}") for i in ("eth0", "lan0"))
        )
    )


def _mac_to_bytes(mac_str: str) -> bytes:
    parts = mac_str.strip().replace("-", ":").split(":")
    return bytes(int(b, 16) for b in parts)


def _ip_to_bytes(ip_str: str) -> bytes:
    return socket.inet_aton(ip_str.strip())


def _build_arp_packet(
    eth_src_mac: str,
    eth_dst_mac: str,
    arp_op: int,
    sender_mac: str,
    sender_ip: str,
    target_mac: str,
    target_ip: str,
) -> bytes:
    """Construct a raw 42-byte Ethernet + IPv4 ARP packet."""
    eth_dst = _mac_to_bytes(eth_dst_mac)
    eth_src = _mac_to_bytes(eth_src_mac)
    eth_header = struct.pack("!6s6sH", eth_dst, eth_src, 0x0806)

    sha = _mac_to_bytes(sender_mac)
    spa = _ip_to_bytes(sender_ip)
    tha = _mac_to_bytes(target_mac)
    tpa = _ip_to_bytes(target_ip)

    arp_payload = struct.pack(
        "!HHBBH6s4s6s4s",
        1,       # Hardware type: Ethernet (1)
        0x0800,  # Protocol type: IPv4 (0x0800)
        6,       # Hardware address length
        4,       # Protocol address length
        arp_op,  # Opcode: 1=Request, 2=Reply
        sha,
        spa,
        tha,
        tpa,
    )
    return eth_header + arp_payload


def _get_interface_mac_and_ip(iface: str) -> tuple[str | None, str | None]:
    mac = None
    ip = None
    try:
        mac_path = f"/sys/class/net/{iface}/address"
        if os.path.exists(mac_path):
            with open(mac_path, "r", encoding="utf-8") as f:
                mac = f.read().strip().upper()
    except Exception:
        pass

    try:
        res = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", iface, "scope", "global"],
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and "/" in parts[3]:
                ip = parts[3].split("/")[0]
                break
    except Exception:
        pass

    return mac, ip


def _get_neighbor_mac_map() -> dict[str, str]:
    """Return {ip_address: mac_address} from the kernel neighbor table."""
    mapping: dict[str, str] = {}
    try:
        res = subprocess.run(
            ["ip", "-4", "neigh", "show"],
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and "lladdr" in parts:
                idx = parts.index("lladdr")
                if idx + 1 < len(parts):
                    ip_addr = parts[0].strip()
                    mac_addr = parts[idx + 1].strip().upper()
                    if len(mac_addr) == 17:
                        mapping[ip_addr] = mac_addr
    except Exception:
        pass
    return mapping


def _is_interface_carrier_up(iface: str) -> bool:
    """Check if interface is operationally up and has active link carrier."""
    try:
        oper_file = f"/sys/class/net/{iface}/operstate"
        if os.path.exists(oper_file):
            with open(oper_file, "r", encoding="utf-8") as f:
                if f.read().strip().lower() == "down":
                    return False
        carrier_file = f"/sys/class/net/{iface}/carrier"
        if os.path.exists(carrier_file):
            with open(carrier_file, "r", encoding="utf-8") as f:
                if f.read().strip() == "0":
                    return False
        return True
    except Exception:
        return True


def _get_active_gateways() -> list[dict]:
    """
    Detect all default IPv4 gateways across eth0 and wlan0 along with their MACs.
    Only active interfaces with operational link carrier are used.
    """
    neigh_map = _get_neighbor_mac_map()
    gateways: list[dict] = []
    seen: set[tuple[str, str]] = set()

    try:
        res = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )
        for line in res.stdout.splitlines():
            parts = line.split()
            if "via" in parts and "dev" in parts:
                gw_ip = parts[parts.index("via") + 1]
                iface = parts[parts.index("dev") + 1]
                key = (iface, gw_ip)
                if key in seen:
                    continue
                seen.add(key)

                iface_mac, iface_ip = _get_interface_mac_and_ip(iface)
                gw_mac = neigh_map.get(gw_ip)
                if iface_mac and iface_ip:
                    gateways.append({
                        "interface": iface,
                        "iface_mac": iface_mac,
                        "iface_ip": iface_ip,
                        "gw_ip": gw_ip,
                        "gw_mac": gw_mac,
                    })
    except Exception:
        pass

    # Deduplicate gateways by gw_ip to prevent cross-interface ARP storms.
    # Discard any gateway interface that has no carrier / link down.
    deduped: dict[str, dict] = {}
    for gw in gateways:
        gw_ip = gw["gw_ip"]
        iface = gw["interface"]
        if not _is_interface_carrier_up(iface):
            continue
        if gw_ip not in deduped:
            deduped[gw_ip] = gw
        else:
            curr_iface = deduped[gw_ip]["interface"]
            if not _is_interface_carrier_up(curr_iface):
                deduped[gw_ip] = gw
            elif iface.startswith("eth") or iface.startswith("en"):
                deduped[gw_ip] = gw

    return list(deduped.values()) or gateways


def _run_iptables(args: list[str]) -> bool:
    if _is_cloud_host():
        return True
    for prefix in (["sudo", "-n", "/usr/sbin/iptables"], ["/usr/sbin/iptables"]):
        try:
            res = subprocess.run(
                prefix + args,
                capture_output=True,
                text=True,
                check=False,
                timeout=2,
            )
            if res.returncode == 0:
                return True
        except Exception:
            continue
    return False


def ensure_iptables_quarantine_chain() -> None:
    global _iptables_initialized, _currently_blocked_ips
    if _is_test_env() or _iptables_initialized:
        return

    try:
        # Ensure chain exists
        _run_iptables(["-N", IPTABLES_CHAIN])
        # Ensure jump from FORWARD to IPTABLES_CHAIN is at top
        if not _run_iptables(["-C", "FORWARD", "-j", IPTABLES_CHAIN]):
            _run_iptables(["-I", "FORWARD", "1", "-j", IPTABLES_CHAIN])
        # Ensure jump from INPUT to IPTABLES_CHAIN is at top
        if not _run_iptables(["-C", "INPUT", "-j", IPTABLES_CHAIN]):
            _run_iptables(["-I", "INPUT", "1", "-j", IPTABLES_CHAIN])

        # Discover existing rules
        for prefix in (["/usr/sbin/iptables"], ["sudo", "-n", "/usr/sbin/iptables"]):
            try:
                res = subprocess.run(
                    prefix + ["-L", IPTABLES_CHAIN, "-n"],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=2,
                )
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] in ("REJECT", "DROP"):
                            src = parts[3]
                            if src.startswith("192.168.0."):
                                _currently_blocked_ips.add(src)
                    break
            except Exception:
                continue

        _iptables_initialized = True
    except Exception as exc:
        logger.debug(f"iptables chain init note: {exc}")


def add_iptables_quarantine_ip(ip_address: str, mac_address: str | None = None) -> None:
    if _is_test_env() or not ip_address or is_protected(ip_address, mac_address):
        return
    ensure_iptables_quarantine_chain()
    if ip_address not in _currently_blocked_ips:
        # 1. Immediate TCP RST rejection for instant TCP connection drop
        if not _run_iptables(["-C", IPTABLES_CHAIN, "-s", ip_address, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"]):
            _run_iptables(["-I", IPTABLES_CHAIN, "1", "-s", ip_address, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"])
        # 2. Immediate ICMP host-prohibited rejection for UDP (DNS 53, QUIC 443) and ICMP
        if not _run_iptables(["-C", IPTABLES_CHAIN, "-s", ip_address, "-j", "REJECT", "--reject-with", "icmp-host-prohibited"]):
            _run_iptables(["-I", IPTABLES_CHAIN, "2", "-s", ip_address, "-j", "REJECT", "--reject-with", "icmp-host-prohibited"])
        # 3. Fallback drop for outbound & inbound
        if not _run_iptables(["-C", IPTABLES_CHAIN, "-s", ip_address, "-j", "DROP"]):
            _run_iptables(["-I", IPTABLES_CHAIN, "3", "-s", ip_address, "-j", "DROP"])
        if not _run_iptables(["-C", IPTABLES_CHAIN, "-d", ip_address, "-j", "DROP"]):
            _run_iptables(["-I", IPTABLES_CHAIN, "4", "-d", ip_address, "-j", "DROP"])
        _currently_blocked_ips.add(ip_address)

    if mac_address and not is_protected(None, mac_address):
        clean_mac = mac_address.strip().upper()
        if not _run_iptables(["-C", IPTABLES_CHAIN, "-m", "mac", "--mac-source", clean_mac, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"]):
            _run_iptables(["-I", IPTABLES_CHAIN, "1", "-m", "mac", "--mac-source", clean_mac, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"])
        if not _run_iptables(["-C", IPTABLES_CHAIN, "-m", "mac", "--mac-source", clean_mac, "-j", "REJECT", "--reject-with", "icmp-host-prohibited"]):
            _run_iptables(["-I", IPTABLES_CHAIN, "2", "-m", "mac", "--mac-source", clean_mac, "-j", "REJECT", "--reject-with", "icmp-host-prohibited"])
        if not _run_iptables(["-C", IPTABLES_CHAIN, "-m", "mac", "--mac-source", clean_mac, "-j", "DROP"]):
            _run_iptables(["-I", IPTABLES_CHAIN, "3", "-m", "mac", "--mac-source", clean_mac, "-j", "DROP"])


def remove_iptables_quarantine_ip(ip_address: str, mac_address: str | None = None) -> None:
    if _is_test_env() or not ip_address:
        return
    ensure_iptables_quarantine_chain()
    while _run_iptables(["-D", IPTABLES_CHAIN, "-s", ip_address, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"]):
        pass
    while _run_iptables(["-D", IPTABLES_CHAIN, "-s", ip_address, "-j", "REJECT", "--reject-with", "icmp-host-prohibited"]):
        pass
    while _run_iptables(["-D", IPTABLES_CHAIN, "-s", ip_address, "-j", "DROP"]):
        pass
    while _run_iptables(["-D", IPTABLES_CHAIN, "-d", ip_address, "-j", "DROP"]):
        pass
    while _run_iptables(["-D", IPTABLES_CHAIN, "-s", ip_address, "-j", "REJECT"]):
        pass
    while _run_iptables(["-D", IPTABLES_CHAIN, "-d", ip_address, "-j", "REJECT"]):
        pass
    if mac_address:
        clean_mac = mac_address.strip().upper()
        while _run_iptables(["-D", IPTABLES_CHAIN, "-m", "mac", "--mac-source", clean_mac, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"]):
            pass
        while _run_iptables(["-D", IPTABLES_CHAIN, "-m", "mac", "--mac-source", clean_mac, "-j", "REJECT", "--reject-with", "icmp-host-prohibited"]):
            pass
        while _run_iptables(["-D", IPTABLES_CHAIN, "-m", "mac", "--mac-source", clean_mac, "-j", "DROP"]):
            pass
    _currently_blocked_ips.discard(ip_address)


def _send_arp_frames(iface: str, frames: list[bytes]) -> None:
    if not frames:
        return
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        try:
            sock.bind((iface, 0))
            for frame in frames:
                sock.send(frame)
        finally:
            sock.close()
    except Exception as exc:
        logger.debug(f"Raw ARP send on {iface} note: {exc}")


def _is_carrier_up(iface: str) -> bool:
    """Check if the physical network interface link carrier is active."""
    try:
        path = f"/sys/class/net/{iface}/carrier"
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return f.read().strip() == "1"
    except Exception:
        pass
    return False


def _build_quarantine_frames_for_target(
    clean_ip: str,
    clean_mac: str,
    gw: dict,
) -> list[bytes]:
    """
    Construct safe targeted unicast ARP Reply (op=2) frames:
    1. Unicast ARP Reply (op=2) to Target Device:
       Tells only the target device that the gateway IP is at our MAC.
    2. Unicast ARP Reply (op=2) to Gateway Router:
       Tells the gateway router that target device IP is at our MAC.

    CRITICAL SAFETY RULES:
    - NEVER emit ARP Requests (op=1) claiming to be the gateway: if the target's MAC
      is not yet learned by an Ethernet switch, the switch floods the request out of
      all ports, causing EVERY computer on the LAN to hijack the gateway IP and disconnect.
    - NEVER broadcast Gratuitous ARP (GARP) with dst_mac=FF:FF:FF:FF:FF:FF: broadcasting
      an IP onto the whole LAN crashes switches and triggers OS address conflict defenses.
    """
    iface_mac = gw["iface_mac"]
    gw_ip = gw["gw_ip"]
    gw_mac = gw.get("gw_mac")
    frames = []

    # 1. Unicast ARP Reply (op=2) to Target Device only
    frames.append(
        _build_arp_packet(
            eth_src_mac=iface_mac,
            eth_dst_mac=clean_mac,
            arp_op=2,  # Unicast reply only
            sender_mac=iface_mac,
            sender_ip=gw_ip,
            target_mac=clean_mac,
            target_ip=clean_ip,
        )
    )

    # 2. Unicast ARP Reply (op=2) to Gateway Router only
    if gw_mac and gw_mac != clean_mac:
        frames.append(
            _build_arp_packet(
                eth_src_mac=iface_mac,
                eth_dst_mac=gw_mac,
                arp_op=2,  # Unicast reply only
                sender_mac=iface_mac,
                sender_ip=clean_ip,
                target_mac=gw_mac,
                target_ip=gw_ip,
            )
        )

    return frames


def _get_target_interface(target_ip: str) -> str | None:
    """Determine which physical interface (wlan0 or eth0) the target device is reachable on."""
    try:
        res = subprocess.run(
            ["ip", "-4", "neigh", "show", target_ip],
            capture_output=True,
            text=True,
            check=False,
            timeout=1,
        )
        for line in res.stdout.splitlines():
            # Disregard incomplete or failed entries
            if "FAILED" in line or "INCOMPLETE" in line:
                continue
            parts = line.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return None


def _continuous_quarantine_worker() -> None:
    """
    Background worker loop that continuously transmits unicast ARP poison frames
    every 0.5 seconds for actively quarantined targets.
    """
    global _worker_running
    logger.info("NETOPS Layer 2 continuous quarantine background worker started.")
    last_gw_refresh = 0.0
    cached_gateways: list[dict] = []

    while _worker_running:
        try:
            with _quarantine_lock:
                targets = dict(_active_quarantine_targets)

            if not targets:
                time.sleep(0.5)
                continue

            now = time.time()
            if now - last_gw_refresh > 10.0 or not cached_gateways:
                cached_gateways = _get_active_gateways()
                last_gw_refresh = now

            if not cached_gateways:
                time.sleep(0.5)
                continue

            for target_ip, info in list(targets.items()):
                clean_mac = info.get("mac")
                if not clean_mac or is_protected(target_ip, clean_mac):
                    with _quarantine_lock:
                        _active_quarantine_targets.pop(target_ip, None)
                    continue

                req_iface = info.get("interface") or _get_target_interface(target_ip)

                for gw in cached_gateways:
                    iface = gw["interface"]
                    if not _is_carrier_up(iface):
                        continue
                    if req_iface and req_iface != "all" and iface != req_iface:
                        continue
                    if target_ip == gw["iface_ip"] or clean_mac == gw["iface_mac"]:
                        continue

                    frames = _build_quarantine_frames_for_target(target_ip, clean_mac, gw)
                    _send_arp_frames(iface, frames)

        except Exception as exc:
            logger.debug(f"Continuous quarantine worker exception: {exc}")

        time.sleep(0.5)


def _start_quarantine_worker() -> None:
    """Ensure the continuous quarantine worker thread is alive."""
    global _worker_thread, _worker_running
    if _is_test_env() or _is_cloud_host():
        return
    with _quarantine_lock:
        if not _worker_running or _worker_thread is None or not _worker_thread.is_alive():
            _worker_running = True
            _worker_thread = threading.Thread(
                target=_continuous_quarantine_worker,
                daemon=True,
                name="NETOPS_L2_Quarantine_Worker",
            )
            _worker_thread.start()


def quarantine_device_l2(
    ip_address: str | None,
    mac_address: str | None,
    burst: int = 5,
    interface: str | None = None,
) -> bool:
    """
    Immediately cut off a LAN or Wi-Fi (wlan0) device from the internet by:
    1. Blocking its IP in the kernel FORWARD chain (REJECT outbound, DROP inbound)
    2. Enrolling the device into the active continuous ARP quarantine registry
    3. Emitting an immediate rapid burst of dual ARP Reply + Request poison frames
    4. Flushing local kernel neighbor cache
    """
    if _is_test_env() or _is_cloud_host() or not ip_address or not mac_address:
        return False

    clean_ip = ip_address.strip()
    clean_mac = mac_address.strip().upper()
    if is_protected(clean_ip, clean_mac) or not clean_ip.startswith("192.168.0."):
        logger.info(f"[IMMUNE] Skipping L2 quarantine for protected/external device: {clean_ip} ({clean_mac})")
        return False

    # 1. Kernel iptables rule
    add_iptables_quarantine_ip(clean_ip, clean_mac)

    # 2. Register into continuous poison worker
    with _quarantine_lock:
        _active_quarantine_targets[clean_ip] = {
            "mac": clean_mac,
            "interface": interface,
            "enrolled_at": time.time(),
        }

    # 3. Ensure background worker is active
    _start_quarantine_worker()

    # 4. Flush local neighbor cache to drop existing cached routing immediately
    try:
        subprocess.run(
            ["ip", "-4", "neigh", "flush", "to", clean_ip],
            capture_output=True,
            check=False,
            timeout=1,
        )
    except Exception:
        pass
    try:
        subprocess.run(
            ["ss", "-K", "dst", clean_ip],
            capture_output=True,
            check=False,
            timeout=1,
        )
        subprocess.run(
            ["ss", "-K", "src", clean_ip],
            capture_output=True,
            check=False,
            timeout=1,
        )
    except Exception:
        pass

    # 5. Immediate rapid burst for instantaneous (< 20ms) severance
    gateways = _get_active_gateways()
    for gw in gateways:
        iface = gw["interface"]
        if interface and interface != "all" and iface != interface:
            continue
        if clean_ip == gw["iface_ip"] or clean_mac == gw["iface_mac"]:
            continue

        frames = _build_quarantine_frames_for_target(clean_ip, clean_mac, gw)
        for _ in range(max(1, burst)):
            _send_arp_frames(iface, frames)
            if burst > 1:
                time.sleep(0.01)

    return True


def restore_device_l2(
    ip_address: str | None,
    mac_address: str | None,
    burst: int = 5,
    interface: str | None = None,
) -> bool:
    """
    Restore normal internet access for a previously quarantined/isolated device on
    Wi-Fi (wlan0) or LAN (eth0) by:
    1. Deregistering from the continuous poison worker
    2. Removing the kernel iptables blocks
    3. Emitting authentic unicast & Gratuitous ARP (GARP) broadcast restoration frames
       with true hardware Ethernet MACs for immediate recovery (< 50ms)
    4. Flushing local kernel neighbor cache
    """
    if _is_test_env() or _is_cloud_host() or not ip_address or not mac_address:
        return False

    clean_ip = ip_address.strip()
    clean_mac = mac_address.strip().upper()

    # 1. Unregister from continuous poison loop
    with _quarantine_lock:
        _active_quarantine_targets.pop(clean_ip, None)

    # 2. Remove kernel iptables block
    remove_iptables_quarantine_ip(clean_ip, clean_mac)

    # 3. Flush local neighbor cache
    try:
        subprocess.run(
            ["ip", "-4", "neigh", "flush", "to", clean_ip],
            capture_output=True,
            check=False,
            timeout=1,
        )
    except Exception:
        pass

    # 4. Restore true ARP mapping between gateway and target device
    gateways = _get_active_gateways()
    bcast_mac = "FF:FF:FF:FF:FF:FF"
    zero_mac = "00:00:00:00:00:00"

    for gw in gateways:
        iface = gw["interface"]
        if interface and interface != "all" and iface != interface:
            continue
        gw_ip = gw["gw_ip"]
        gw_mac = gw.get("gw_mac")

        if not gw_mac:
            continue

        frames = [
            # 1. Authentic Unicast to Client: Router is at gw_mac (Reply + Request)
            _build_arp_packet(gw_mac, clean_mac, 2, gw_mac, gw_ip, clean_mac, clean_ip),
            _build_arp_packet(gw_mac, clean_mac, 1, gw_mac, gw_ip, clean_mac, clean_ip),

            # 2. Authentic Unicast to Gateway: Client is at clean_mac (Reply + Request)
            _build_arp_packet(clean_mac, gw_mac, 2, clean_mac, clean_ip, gw_mac, gw_ip),
            _build_arp_packet(clean_mac, gw_mac, 1, clean_mac, clean_ip, gw_mac, gw_ip),

            # 3. Gratuitous ARP (GARP) Broadcasts to update switches, APs, and endpoints
            _build_arp_packet(gw_mac, bcast_mac, 2, gw_mac, gw_ip, bcast_mac, gw_ip),
            _build_arp_packet(gw_mac, bcast_mac, 1, gw_mac, gw_ip, zero_mac, gw_ip),
            _build_arp_packet(clean_mac, bcast_mac, 2, clean_mac, clean_ip, bcast_mac, clean_ip),
            _build_arp_packet(clean_mac, bcast_mac, 1, clean_mac, clean_ip, zero_mac, clean_ip),
        ]

        for _ in range(max(1, burst)):
            _send_arp_frames(iface, frames)
            if burst > 1:
                time.sleep(0.01)

    return True


def get_quarantined_l2_targets() -> list[dict]:
    """Return all currently active continuous L2 quarantine targets."""
    with _quarantine_lock:
        return [
            {"ip_address": ip, "mac_address": info["mac"], "interface": info.get("interface")}
            for ip, info in _active_quarantine_targets.items()
        ]


def is_target_quarantined(ip_address: str | None, mac_address: str | None = None) -> bool:
    """Check if an IP or MAC is currently registered in L2 quarantine or blocked in iptables."""
    if not ip_address and not mac_address:
        return False
    if ip_address and ip_address in _currently_blocked_ips:
        return True
    with _quarantine_lock:
        if ip_address and ip_address in _active_quarantine_targets:
            return True
        if mac_address:
            clean_mac = mac_address.strip().upper()
            if any(info.get("mac") == clean_mac for info in _active_quarantine_targets.values()):
                return True
    return False


def clear_all_l2_quarantines() -> None:
    """Restore all quarantined targets and clear active registry."""
    with _quarantine_lock:
        targets = dict(_active_quarantine_targets)
        _active_quarantine_targets.clear()
    for ip, info in targets.items():
        try:
            restore_device_l2(ip, info["mac"], interface=info.get("interface"))
        except Exception:
            pass
    _run_iptables(["-F", IPTABLES_CHAIN])
    _currently_blocked_ips.clear()


def sync_quarantined_targets_from_db(db=None) -> int:
    """
    Enrolls all currently quarantined/isolated devices in the database
    into the active continuous L2 quarantine worker.
    """
    if _is_test_env() or _is_cloud_host():
        return 0
    from ..models.device import Device
    close_db = False
    if db is None:
        try:
            from ..database import SessionLocal
            db = SessionLocal()
            close_db = True
        except Exception:
            return 0
    try:
        devices = db.query(Device).filter(
            Device.enforcement_status.in_(["quarantined", "isolated"]),
            Device.ip_address.isnot(None),
        ).all()
        enrolled = 0
        for dev in devices:
            if dev.ip_address and dev.mac_address and not is_protected(dev.ip_address, dev.mac_address):
                quarantine_device_l2(
                    dev.ip_address,
                    dev.mac_address,
                    burst=3,
                    interface=getattr(dev, "network_interface", None),
                )
                enrolled += 1
        logger.info(f"[L2 Quarantine] Synchronized {enrolled} quarantined target(s) from database.")
        return enrolled
    except Exception as exc:
        logger.debug(f"[L2 Quarantine] Database sync note: {exc}")
        return 0
    finally:
        if close_db and db:
            db.close()

