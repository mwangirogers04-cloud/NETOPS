import socket
import struct
from unittest.mock import MagicMock, patch

from backend.app.models.device import Device
from backend.app.services.passive_sniffer import (
    process_sniffed_packet,
    start_passive_sniffer,
    stop_passive_sniffer,
    _known_macs_cache,
)


def make_arp_frame(src_mac_str: str, src_ip_str: str) -> bytes:
    dst_bytes = b"\xff" * 6
    src_bytes = bytes(int(b, 16) for b in src_mac_str.split(":"))
    eth = struct.pack("!6s6sH", dst_bytes, src_bytes, 0x0806)

    sha = src_bytes
    spa = socket.inet_aton(src_ip_str)
    tha = b"\x00" * 6
    tpa = socket.inet_aton("192.168.0.1")
    arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, sha, spa, tha, tpa)
    return eth + arp


def make_ipv4_frame(src_mac_str: str, src_ip_str: str) -> bytes:
    dst_bytes = bytes(int(b, 16) for b in "00:11:22:33:44:55".split(":"))
    src_bytes = bytes(int(b, 16) for b in src_mac_str.split(":"))
    eth = struct.pack("!6s6sH", dst_bytes, src_bytes, 0x0800)

    # 20-byte IP header with src_ip at offset 12
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 40, 1, 0, 64, 6, 0,
        socket.inet_aton(src_ip_str),
        socket.inet_aton("192.168.0.1"),
    )
    return eth + ip_hdr


def test_ignores_multicast_and_broadcast():
    bcast_frame = struct.pack("!6s6sH", b"\xff" * 6, b"\xff" * 6, 0x0806)
    mcast_frame = struct.pack("!6s6sH", b"\xff" * 6, b"\x01\x00\x5e\x00\x00\x01", 0x0800)

    with patch("backend.app.services.passive_sniffer.SessionLocal") as mock_session:
        process_sniffed_packet(bcast_frame, "eth0")
        process_sniffed_packet(mcast_frame, "eth0")
        mock_session.assert_not_called()


def test_process_sniffed_packet_creates_quarantined_device():
    test_mac = "02:CC:DD:EE:FF:11"
    test_ip = "192.168.0.77"
    frame = make_arp_frame(test_mac, test_ip)

    _known_macs_cache.discard(test_mac)

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None

    with patch("backend.app.services.passive_sniffer.SessionLocal", return_value=mock_db), \
         patch("backend.app.services.passive_sniffer.quarantine_device_l2") as mock_l2, \
         patch("backend.app.services.passive_sniffer.create_event"):

        process_sniffed_packet(frame, "eth0")

        # Verify device was added to DB
        mock_db.add.assert_called_once()
        added_device = mock_db.add.call_args[0][0]

        assert added_device.mac_address == test_mac
        assert added_device.ip_address == test_ip
        assert added_device.approval_status == "pending"
        assert added_device.vlan_id == 90
        assert added_device.enforcement_status == "quarantined"
        assert added_device.internet_access_authorized is False

        # Verify L2 quarantine was triggered immediately
        mock_l2.assert_called_once_with(test_ip, test_mac, interface="eth0")

        # Verify MAC is now in known cache so subsequent packets are ignored
        assert test_mac in _known_macs_cache


def test_start_and_stop_passive_sniffer_lifecycle():
    # In test environment, it safely skips starting thread
    start_passive_sniffer()
    stop_passive_sniffer()
