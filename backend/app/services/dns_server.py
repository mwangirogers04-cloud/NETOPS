import logging
import socket
import threading
import time

import dns.message
import dns.query
import dns.rdatatype

from ..database import SessionLocal
from .web_traffic_sniffer import record_web_activity, get_or_create_web_policy
from .web_categorizer import categorize_domain, is_prohibited_during_work

logger = logging.getLogger(__name__)

UPSTREAM_DNS_SERVERS = ["1.1.1.1", "8.8.8.8"]
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 53  # Standard DNS port (unprivileged port start is 0 on Kali)

_dns_server_running = False
_dns_socket: socket.socket | None = None
_dns_thread: threading.Thread | None = None


def _handle_dns_query(data: bytes, client_addr: tuple[str, int], server_sock: socket.socket):
    """Process incoming DNS query, record activity, and forward response."""
    client_ip = client_addr[0]
    domain = None
    try:
        msg = dns.message.from_wire(data)
        if msg.question:
            q = msg.question[0]
            domain = str(q.name).strip().rstrip(".").lower()
    except Exception:
        domain = None

    if domain:
        # Record web activity in NetOps
        try:
            with SessionLocal() as db:
                record_web_activity(db, client_ip, domain, protocol="DNS")
        except Exception as exc:
            logger.debug(f"[DNS_SERVER] Activity record note: {exc}")

    # Forward to upstream resolver
    resp_data = None
    for upstream in UPSTREAM_DNS_SERVERS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_sock:
                upstream_sock.settimeout(2.0)
                upstream_sock.sendto(data, (upstream, 53))
                resp_data, _ = upstream_sock.recvfrom(4096)
                if resp_data:
                    break
        except Exception:
            continue

    if resp_data:
        try:
            server_sock.sendto(resp_data, client_addr)
        except Exception as exc:
            logger.debug(f"[DNS_SERVER] Reply error to {client_addr}: {exc}")


def _dns_server_worker():
    """Main UDP listener loop for NetOps DNS forwarder."""
    global _dns_server_running, _dns_socket
    logger.info(f"[DNS_SERVER] Starting DNS forwarder on {LISTEN_HOST}:{LISTEN_PORT}...")

    try:
        _dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _dns_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _dns_socket.bind((LISTEN_HOST, LISTEN_PORT))
        _dns_socket.settimeout(1.0)
    except Exception as exc:
        logger.error(f"[DNS_SERVER] Failed to bind to {LISTEN_HOST}:{LISTEN_PORT}: {exc}")
        _dns_server_running = False
        return

    logger.info(f"[DNS_SERVER] Live on {LISTEN_HOST}:{LISTEN_PORT} - Ready to log laptop and phone traffic!")

    while _dns_server_running:
        try:
            data, client_addr = _dns_socket.recvfrom(4096)
            if not data:
                continue
            # Process in thread pool or fast thread so queries are instantaneous
            t = threading.Thread(
                target=_handle_dns_query,
                args=(data, client_addr, _dns_socket),
                daemon=True,
            )
            t.start()
        except socket.timeout:
            continue
        except Exception as exc:
            if _dns_server_running:
                logger.error(f"[DNS_SERVER] Loop error: {exc}")
            time.sleep(0.5)

    if _dns_socket:
        try:
            _dns_socket.close()
        except Exception:
            pass
        _dns_socket = None


def start_dns_server():
    """Start the built-in NetOps DNS forwarder service in a background thread."""
    global _dns_server_running, _dns_thread
    if _dns_server_running:
        return
    _dns_server_running = True
    _dns_thread = threading.Thread(
        target=_dns_server_worker,
        daemon=True,
        name="netops-dns-forwarder",
    )
    _dns_thread.start()


def stop_dns_server():
    """Stop the DNS forwarder."""
    global _dns_server_running, _dns_socket
    _dns_server_running = False
    if _dns_socket:
        try:
            _dns_socket.close()
        except Exception:
            pass
        _dns_socket = None
