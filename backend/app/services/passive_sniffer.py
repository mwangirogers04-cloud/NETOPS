import logging
import os
import select
import socket
import struct
import threading
import time
from datetime import datetime
from typing import Any

from ..database import SessionLocal
from ..models.device import Device
from ..models.event import Event
from .event_service import create_event
from .device_classifier import classify_device
from .l2_quarantine import quarantine_device_l2, PROTECTED_IPS

logger = logging.getLogger(__name__)

_known_macs_cache: set[str] = set()
_sniffer_thread: threading.Thread | None = None
_stop_event = threading.Event()
_local_host_macs: set[str] = set()


def _is_test_env() -> bool:
    return bool(os.environ.get("PYTEST_CURRENT_TEST"))


def _refresh_local_host_macs() -> None:
    global _local_host_macs
    macs = set()
    for iface in ("eth0", "wlan0", "lo"):
        try:
            path = f"/sys/class/net/{iface}/address"
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    m = f.read().strip().upper()
                    if len(m) == 17:
                        macs.add(m)
        except Exception:
            pass
    _local_host_macs = macs


def load_known_macs_from_db() -> None:
    """Pre-populate the known MACs cache from the devices database."""
    global _known_macs_cache
    _refresh_local_host_macs()
    try:
        db = SessionLocal()
        try:
            records = db.query(Device.mac_address).all()
            _known_macs_cache = {
                r[0].upper().strip() for r in records if r[0]
            }
        finally:
            db.close()
    except Exception as exc:
        logger.debug(f"[SNIFFER] Cache init note: {exc}")


def process_sniffed_packet(data: bytes, iface: str) -> None:
    """
    Parse a raw Ethernet frame captured on eth0 or wlan0.
    If the source MAC is unknown, register it in the database as quarantined
    and immediately enforce Layer 2 / firewall isolation.
    """
    if len(data) < 14:
        return

    # Ethernet header: dst (6), src (6), ethertype (2)
    eth_header = data[:14]
    dst_raw, src_raw, eth_type = struct.unpack("!6s6sH", eth_header)

    src_mac = ":".join(f"{b:02X}" for b in src_raw)
    first_byte = src_raw[0]

    # Ignore multicast (bit 0 set), broadcast (FF:FF:FF:FF:FF:FF), or local host MACs
    if (first_byte & 0x01) or src_mac == "FF:FF:FF:FF:FF:FF" or src_mac in _local_host_macs:
        return

    # If already known and tracked, skip processing
    if src_mac in _known_macs_cache:
        return

    src_ip: str | None = None

    # Parse ARP (0x0806)
    if eth_type == 0x0806 and len(data) >= 42:
        try:
            arp_payload = data[14:42]
            spa = arp_payload[14:18]
            cand_ip = socket.inet_ntoa(spa)
            if cand_ip != "0.0.0.0" and cand_ip.startswith("192.168.0."):
                src_ip = cand_ip
        except Exception:
            pass

    # Parse IPv4 (0x0800)
    elif eth_type == 0x0800 and len(data) >= 34:
        try:
            ip_header = data[14:34]
            cand_ip = socket.inet_ntoa(ip_header[12:16])
            if cand_ip != "0.0.0.0" and cand_ip.startswith("192.168.0."):
                src_ip = cand_ip

            # Check if this is a DHCP Discover/Request (UDP port 67/68)
            protocol = ip_header[9]
            if protocol == 17 and len(data) >= 42:  # UDP
                udp_header = data[34:42]
                src_port, dst_port = struct.unpack("!HH", udp_header[:4])
                if dst_port in (67, 68) and len(data) >= 70:
                    dhcp_data = data[42:]
                    # DHCP Client Hardware Address is at offset 28 in DHCP payload
                    if len(dhcp_data) >= 34:
                        chaddr = dhcp_data[28:34]
                        chaddr_mac = ":".join(f"{b:02X}" for b in chaddr)
                        if len(chaddr_mac) == 17 and chaddr_mac != "00:00:00:00:00:00":
                            src_mac = chaddr_mac
        except Exception:
            pass

    # Double check if MAC is in cache after DHCP extraction
    if src_mac in _known_macs_cache or src_mac in _local_host_macs:
        return

    # New device discovered in real time!
    _known_macs_cache.add(src_mac)
    logger.info(f"[PASSIVE-SNIFFER] Captured new device on {iface}: MAC={src_mac}, IP={src_ip}")

    # Register device in database as Quarantine (VLAN 90, unapproved, no internet access)
    try:
        db = SessionLocal()
        try:
            existing = db.query(Device).filter(Device.mac_address == src_mac).first()
            if not existing:
                dev_type = classify_device(
                    hostname=None,
                    vendor=None,
                    mac_address=src_mac,
                )
                new_dev = Device(
                    mac_address=src_mac,
                    ip_address=src_ip,
                    hostname=f"Device-{src_ip.replace('.', '-')}" if src_ip else None,
                    vendor=None,
                    device_type=dev_type or "unknown",
                    network_interface=iface,
                    classification_status="normal",
                    status="offline",
                    approval_status="pending",
                    ip_assignment="dhcp",
                    vlan_id=90,
                    enforcement_status="quarantined",
                    internet_access_authorized=False,
                )
                db.add(new_dev)
                db.commit()
                db.refresh(new_dev)

                create_event(
                    db,
                    "new_device",
                    (
                        f"Real-time passive sniffer detected new machine on {iface}: "
                        f"{src_ip or 'Awaiting DHCP'} ({src_mac}). "
                        f"Zero-Trust Policy: Automatically placed in VLAN 90 Quarantine. "
                        f"Internet access blocked until approved."
                    ),
                    new_dev.id,
                )
                db.commit()

                # Immediately enforce Layer 2 and firewall isolation
                if src_ip and src_ip not in PROTECTED_IPS:
                    try:
                        quarantine_device_l2(src_ip, src_mac, interface=iface)
                    except Exception as q_err:
                        logger.debug(f"[PASSIVE-SNIFFER] Quarantine error: {q_err}")

            elif src_ip and not existing.ip_address:
                existing.ip_address = src_ip
                db.commit()
                if existing.enforcement_status in ("quarantined", "isolated") or not existing.internet_access_authorized:
                    quarantine_device_l2(src_ip, src_mac, interface=iface)

        finally:
            db.close()
    except Exception as db_err:
        logger.error(f"[PASSIVE-SNIFFER] Error saving captured device: {db_err}")


def _sniffer_worker() -> None:
    """Worker loop that monitors eth0 and wlan0 with raw sockets."""
    load_known_macs_from_db()

    interfaces_to_bind = []
    for iface in ("eth0", "wlan0"):
        if os.path.exists(f"/sys/class/net/{iface}"):
            interfaces_to_bind.append(iface)

    sockets: list[tuple[socket.socket, str]] = []
    for iface in interfaces_to_bind:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.bind((iface, 0))
            sock.setblocking(False)
            sockets.append((sock, iface))
            logger.info(f"[PASSIVE-SNIFFER] Bound raw sniffer on {iface}")
        except Exception as err:
            logger.warning(f"[PASSIVE-SNIFFER] Could not bind raw socket on {iface}: {err}")

    if not sockets:
        logger.warning("[PASSIVE-SNIFFER] No raw sockets could be bound. Sniffer disabled.")
        return

    sock_map = {s.fileno(): (s, iface) for s, iface in sockets}

    while not _stop_event.is_set():
        try:
            rlist, _, _ = select.select([s for s, _ in sockets], [], [], 1.0)
            for s in rlist:
                _, iface = sock_map[s.fileno()]
                try:
                    data = s.recv(2048)
                    if data:
                        process_sniffed_packet(data, iface)
                except (BlockingIOError, InterruptedError):
                    continue
                except Exception as recv_err:
                    logger.debug(f"[PASSIVE-SNIFFER] recv error on {iface}: {recv_err}")
        except Exception as loop_err:
            if not _stop_event.is_set():
                logger.debug(f"[PASSIVE-SNIFFER] Loop note: {loop_err}")
                time.sleep(0.5)

    for s, _ in sockets:
        try:
            s.close()
        except Exception:
            pass
    logger.info("[PASSIVE-SNIFFER] Worker stopped gracefully.")


def start_passive_sniffer() -> None:
    """Start the real-time passive network sniffer background thread."""
    global _sniffer_thread, _stop_event
    if _is_test_env():
        return
    if _sniffer_thread and _sniffer_thread.is_alive():
        return

    _stop_event.clear()
    _sniffer_thread = threading.Thread(
        target=_sniffer_worker,
        name="NetopsPassiveSniffer",
        daemon=True,
    )
    _sniffer_thread.start()
    logger.info("[PASSIVE-SNIFFER] Background thread launched.")


def stop_passive_sniffer() -> None:
    """Stop the real-time passive network sniffer background thread."""
    global _sniffer_thread, _stop_event
    _stop_event.set()
    if _sniffer_thread and _sniffer_thread.is_alive():
        _sniffer_thread.join(timeout=2.0)
    _sniffer_thread = None
