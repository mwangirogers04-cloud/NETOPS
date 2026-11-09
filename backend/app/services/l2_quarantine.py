import logging
import os
import socket
import struct
import subprocess
import threading
import time

logger = logging.getLogger(__name__)

PROTECTED_IPS = {
    "127.0.0.1",
    "0.0.0.0",
    "192.168.0.1",    # Wi-Fi Router / Gateway (Tenda)
    "192.168.0.10",   # Sophos Firewall
    "192.168.0.11",   # MikroTik Router
    "192.168.0.13",   # NETOPS Server (eth0)
    "192.168.0.101",  # NETOPS Server (wlan0)
}

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
        not os.path.exists("/sys/class/net/wlan0")
        and not any(os.path.exists(f"/sys/class/net/{i}") for i in ("eth0", "lan0"))
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


def _get_active_gateways() -> list[dict]:
    """
    Detect all default IPv4 gateways across eth0 and wlan0 along with their MACs.
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

    return gateways


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
    global _iptables_initialized
    if _is_test_env() or _iptables_initialized:
        return

    try:
        # Ensure chain exists
        _run_iptables(["-N", IPTABLES_CHAIN])
        # Ensure jump from FORWARD to IPTABLES_CHAIN is at top
        if not _run_iptables(["-C", "FORWARD", "-j", IPTABLES_CHAIN]):
            _run_iptables(["-I", "FORWARD", "1", "-j", IPTABLES_CHAIN])
        _iptables_initialized = True
    except Exception as exc:
        logger.debug(f"iptables chain init note: {exc}")


def add_iptables_quarantine_ip(ip_address: str) -> None:
    if _is_test_env() or not ip_address or ip_address in PROTECTED_IPS:
        return
    ensure_iptables_quarantine_chain()
    if not _run_iptables(["-C", IPTABLES_CHAIN, "-s", ip_address, "-j", "REJECT"]):
        _run_iptables(["-I", IPTABLES_CHAIN, "1", "-s", ip_address, "-j", "REJECT"])
    if not _run_iptables(["-C", IPTABLES_CHAIN, "-d", ip_address, "-j", "DROP"]):
        _run_iptables(["-I", IPTABLES_CHAIN, "1", "-d", ip_address, "-j", "DROP"])
    _currently_blocked_ips.add(ip_address)


def remove_iptables_quarantine_ip(ip_address: str) -> None:
    if _is_test_env() or not ip_address:
        return
    ensure_iptables_quarantine_chain()
    while _run_iptables(["-D", IPTABLES_CHAIN, "-s", ip_address, "-j", "REJECT"]):
        pass
    while _run_iptables(["-D", IPTABLES_CHAIN, "-d", ip_address, "-j", "DROP"]):
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


def _build_quarantine_frames_for_target(
    clean_ip: str,
    clean_mac: str,
    gw: dict,
) -> list[bytes]:
    """
    Build both ARP Reply (op=2) and ARP Request (op=1) poison frames.
    Modern OSs (Android, iOS, Windows 10/11) forcibly update ARP tables
    on incoming ARP Requests as required by RFC 826.
    """
    iface_mac = gw["iface_mac"]
    gw_ip = gw["gw_ip"]
    gw_mac = gw.get("gw_mac")
    frames = []

    # 1. Poison Target Device: Tell target device gateway IP is at our MAC
    frames.append(
        _build_arp_packet(
            eth_src_mac=iface_mac,
            eth_dst_mac=clean_mac,
            arp_op=2,  # Reply
            sender_mac=iface_mac,
            sender_ip=gw_ip,
            target_mac=clean_mac,
            target_ip=clean_ip,
        )
    )
    frames.append(
        _build_arp_packet(
            eth_src_mac=iface_mac,
            eth_dst_mac=clean_mac,
            arp_op=1,  # Request
            sender_mac=iface_mac,
            sender_ip=gw_ip,
            target_mac=clean_mac,
            target_ip=clean_ip,
        )
    )

    # 2. Poison Gateway: Tell gateway (e.g. Tenda 192.168.0.1) target IP is at our MAC
    if gw_mac:
        frames.append(
            _build_arp_packet(
                eth_src_mac=iface_mac,
                eth_dst_mac=gw_mac,
                arp_op=2,  # Reply
                sender_mac=iface_mac,
                sender_ip=clean_ip,
                target_mac=gw_mac,
                target_ip=gw_ip,
            )
        )
        frames.append(
            _build_arp_packet(
                eth_src_mac=iface_mac,
                eth_dst_mac=gw_mac,
                arp_op=1,  # Request
                sender_mac=iface_mac,
                sender_ip=clean_ip,
                target_mac=gw_mac,
                target_ip=gw_ip,
            )
        )

    return frames


def _continuous_quarantine_worker() -> None:
    """
    Background worker loop that continuously transmits ARP poison frames
    every 1.5 seconds for all actively quarantined targets.
    This guarantees that devices cannot bypass quarantine even when
    their OS attempts to refresh its ARP cache or receives router broadcast probes.
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
                time.sleep(1.0)
                continue

            now = time.time()
            if now - last_gw_refresh > 10.0 or not cached_gateways:
                cached_gateways = _get_active_gateways()
                last_gw_refresh = now

            if not cached_gateways:
                time.sleep(1.5)
                continue

            for target_ip, info in targets.items():
                clean_mac = info.get("mac")
                req_iface = info.get("interface")
                if not clean_mac:
                    continue

                for gw in cached_gateways:
                    iface = gw["interface"]
                    if req_iface and req_iface != "all" and iface != req_iface:
                        continue
                    if target_ip == gw["iface_ip"] or clean_mac == gw["iface_mac"]:
                        continue

                    frames = _build_quarantine_frames_for_target(target_ip, clean_mac, gw)
                    _send_arp_frames(iface, frames)

        except Exception as exc:
            logger.debug(f"Continuous quarantine worker exception: {exc}")

        time.sleep(1.5)


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
    burst: int = 3,
    interface: str | None = None,
) -> bool:
    """
    Immediately cut off a LAN or Wi-Fi (wlan0) device from the internet by:
    1. Blocking its IP in the kernel FORWARD chain (REJECT outbound, DROP inbound)
    2. Enrolling the device into the active continuous ARP quarantine registry
    3. Emitting an immediate burst of dual ARP Reply + Request poison frames
    """
    if _is_test_env() or _is_cloud_host() or not ip_address or not mac_address:
        return False

    clean_ip = ip_address.strip()
    clean_mac = mac_address.strip().upper()
    if clean_ip in PROTECTED_IPS or not clean_ip.startswith("192.168.0."):
        return False

    # 1. Kernel iptables rule
    add_iptables_quarantine_ip(clean_ip)

    # 2. Register into continuous poison worker
    with _quarantine_lock:
        _active_quarantine_targets[clean_ip] = {
            "mac": clean_mac,
            "interface": interface,
            "enrolled_at": time.time(),
        }

    # 3. Ensure background worker is active
    _start_quarantine_worker()

    # 4. Immediate burst for instantaneous (< 10ms) severance
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
                time.sleep(0.03)

    return True


def restore_device_l2(
    ip_address: str | None,
    mac_address: str | None,
    burst: int = 4,
    interface: str | None = None,
) -> bool:
    """
    Restore normal internet access for a previously quarantined/isolated device on
    Wi-Fi (wlan0) or LAN (eth0) by:
    1. Deregistering from the continuous poison worker
    2. Removing the kernel iptables blocks
    3. Emitting restoration ARP frames containing true gateway & device hardware MACs
    """
    if _is_test_env() or _is_cloud_host() or not ip_address or not mac_address:
        return False

    clean_ip = ip_address.strip()
    clean_mac = mac_address.strip().upper()
    if clean_ip in PROTECTED_IPS or not clean_ip.startswith("192.168.0."):
        return False

    # 1. Unregister from continuous poison loop
    with _quarantine_lock:
        _active_quarantine_targets.pop(clean_ip, None)

    # 2. Remove kernel iptables block
    remove_iptables_quarantine_ip(clean_ip)

    # 3. Restore true ARP mapping between gateway and target device
    gateways = _get_active_gateways()
    for gw in gateways:
        iface = gw["interface"]
        if interface and interface != "all" and iface != interface:
            continue
        iface_mac = gw["iface_mac"]
        gw_ip = gw["gw_ip"]
        gw_mac = gw["gw_mac"]

        if not gw_mac:
            continue

        frames = [
            # Restore true gateway MAC on target device (Reply + Request)
            _build_arp_packet(iface_mac, clean_mac, 2, gw_mac, gw_ip, clean_mac, clean_ip),
            _build_arp_packet(iface_mac, clean_mac, 1, gw_mac, gw_ip, clean_mac, clean_ip),
            # Restore true target device MAC on gateway (Reply + Request)
            _build_arp_packet(iface_mac, gw_mac, 2, clean_mac, clean_ip, gw_mac, gw_ip),
            _build_arp_packet(iface_mac, gw_mac, 1, clean_mac, clean_ip, gw_mac, gw_ip),
        ]

        for _ in range(max(1, burst)):
            _send_arp_frames(iface, frames)
            if burst > 1:
                time.sleep(0.03)

    return True


def get_quarantined_l2_targets() -> list[dict]:
    """Return all currently active continuous L2 quarantine targets."""
    with _quarantine_lock:
        return [
            {"ip_address": ip, "mac_address": info["mac"], "interface": info.get("interface")}
            for ip, info in _active_quarantine_targets.items()
        ]


def clear_all_l2_quarantines() -> None:
    """Restore all quarantined targets and clear active registry."""
    with _quarantine_lock:
        targets = dict(_active_quarantine_targets)
    for ip, info in targets.items():
        try:
            restore_device_l2(ip, info["mac"], interface=info.get("interface"))
        except Exception:
            pass
