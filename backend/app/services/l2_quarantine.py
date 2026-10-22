import logging
import os
import socket
import struct
import subprocess
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


def _is_test_env() -> bool:
    return bool(os.environ.get("PYTEST_CURRENT_TEST"))


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


def quarantine_device_l2(
    ip_address: str | None,
    mac_address: str | None,
    burst: int = 2,
    interface: str | None = None,
) -> bool:
    """
    Immediately cut off a LAN or Wi-Fi (wlan0) device from the internet by:
    1. Blocking its IP in the kernel FORWARD chain (REJECT outbound, DROP inbound)
    2. Sending targeted ARP quarantine frames between the device and the active
       gateways (192.168.0.1 on wlan0 and 192.168.0.10 on eth0).
    """
    if _is_test_env() or not ip_address or not mac_address:
        return False

    clean_ip = ip_address.strip()
    clean_mac = mac_address.strip().upper()
    if clean_ip in PROTECTED_IPS or not clean_ip.startswith("192.168.0."):
        return False

    add_iptables_quarantine_ip(clean_ip)

    gateways = _get_active_gateways()
    for gw in gateways:
        iface = gw["interface"]
        if interface and interface != "all" and iface != interface:
            continue
        iface_mac = gw["iface_mac"]
        gw_ip = gw["gw_ip"]
        gw_mac = gw["gw_mac"]

        if clean_ip == gw["iface_ip"] or clean_mac == iface_mac:
            continue

        frames: list[bytes] = []
        # 1. Tell target device (e.g. 192.168.0.108) that gateway (192.168.0.1 / 192.168.0.10) is at our MAC
        frames.append(
            _build_arp_packet(
                eth_src_mac=iface_mac,
                eth_dst_mac=clean_mac,
                arp_op=2,
                sender_mac=iface_mac,
                sender_ip=gw_ip,
                target_mac=clean_mac,
                target_ip=clean_ip,
            )
        )
        # 2. Tell gateway (e.g. Tenda Wi-Fi router 192.168.0.1) that target device is at our MAC
        if gw_mac:
            frames.append(
                _build_arp_packet(
                    eth_src_mac=iface_mac,
                    eth_dst_mac=gw_mac,
                    arp_op=2,
                    sender_mac=iface_mac,
                    sender_ip=clean_ip,
                    target_mac=gw_mac,
                    target_ip=gw_ip,
                )
            )

        for _ in range(max(1, burst)):
            _send_arp_frames(iface, frames)
            if burst > 1:
                time.sleep(0.04)

    return True


def restore_device_l2(
    ip_address: str | None,
    mac_address: str | None,
    burst: int = 3,
    interface: str | None = None,
) -> bool:
    """
    Restore normal internet access for a previously quarantined/isolated device on
    Wi-Fi (wlan0) or LAN (eth0) by removing the iptables block and broadcasting
    the true gateway MAC address back to the device and gateway.
    """
    if _is_test_env() or not ip_address or not mac_address:
        return False

    clean_ip = ip_address.strip()
    clean_mac = mac_address.strip().upper()
    if clean_ip in PROTECTED_IPS or not clean_ip.startswith("192.168.0."):
        return False

    remove_iptables_quarantine_ip(clean_ip)

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

        frames: list[bytes] = [
            # Restore true gateway MAC on the target device
            _build_arp_packet(
                eth_src_mac=iface_mac,
                eth_dst_mac=clean_mac,
                arp_op=2,
                sender_mac=gw_mac,
                sender_ip=gw_ip,
                target_mac=clean_mac,
                target_ip=clean_ip,
            ),
            # Restore true target device MAC on the gateway
            _build_arp_packet(
                eth_src_mac=iface_mac,
                eth_dst_mac=gw_mac,
                arp_op=2,
                sender_mac=clean_mac,
                sender_ip=clean_ip,
                target_mac=gw_mac,
                target_ip=gw_ip,
            ),
        ]

        for _ in range(max(1, burst)):
            _send_arp_frames(iface, frames)
            if burst > 1:
                time.sleep(0.04)

    return True
