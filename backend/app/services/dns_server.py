import logging
import socket
import select
import threading
import time
import subprocess

import dns.message
import dns.query
import dns.rdatatype
import dns.rcode

from ..database import SessionLocal
from .web_traffic_sniffer import record_web_activity, get_or_create_web_policy
from .web_categorizer import categorize_domain, is_prohibited_during_work

logger = logging.getLogger(__name__)

UPSTREAM_DNS_SERVERS = ["1.1.1.1", "8.8.8.8"]
LISTEN_PORT = 53  # Standard DNS port

_dns_server_running = False
_dns_sockets: list[socket.socket] = []
_dns_thread: threading.Thread | None = None


def get_listening_ips() -> list[str]:
    """Retrieve all local IPv4 interface addresses plus NetOps aliases."""
    ips = set(["127.0.0.1", "192.168.0.101", "192.168.0.111"])
    try:
        res = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True, check=False)
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[3].split("/")[0]
                if not ip.startswith("172.") and not ip.startswith("169.254"):
                    ips.add(ip)
    except Exception:
        pass
    return sorted(list(ips))


def _handle_dns_query(data: bytes, client_addr: tuple[str, int], server_sock: socket.socket):
    """Process incoming DNS query, record activity, and forward response."""
    client_ip = client_addr[0]
    domain = None
    msg = None
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

        # Block / Sinkhole DNS-over-HTTPS (DoH) bootstrap domains and canary domains.
        # When browsers (Chrome, Edge, Firefox) receive NXDOMAIN for these, they
        # immediately disable encrypted DoH and fall back to standard network DNS,
        # allowing all user browsing to be monitored seamlessly.
        doh_domains = {
            "use-application-dns.net",
            "dns.google",
            "dns.google.com",
            "cloudflare-dns.com",
            "one.one.one.one",
            "doh.opendns.com",
            "dns.quad9.net",
            "doh.cleanbrowsing.org",
            "dns.nextdns.io",
        }
        if domain in doh_domains or domain.endswith(".use-application-dns.net"):
            if msg:
                try:
                    reply = dns.message.make_response(msg)
                    reply.set_rcode(dns.rcode.NXDOMAIN)
                    server_sock.sendto(reply.to_wire(), client_addr)
                    return
                except Exception as exc:
                    logger.debug(f"[DNS_SERVER] Error sending DoH fallback reply: {exc}")

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
    """Main UDP listener loop for NetOps DNS forwarder supporting all interface IPs."""
    global _dns_server_running, _dns_sockets
    listen_ips = get_listening_ips()
    logger.info(f"[DNS_SERVER] Initializing DNS listeners on IPs: {listen_ips} port {LISTEN_PORT}...")

    _dns_sockets = []
    for ip in listen_ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((ip, LISTEN_PORT))
            _dns_sockets.append(s)
            logger.info(f"[DNS_SERVER] Bound successfully to {ip}:{LISTEN_PORT}")
        except Exception as exc:
            logger.warning(f"[DNS_SERVER] Could not bind to {ip}:{LISTEN_PORT}: {exc}")

    if not _dns_sockets:
        # Fallback to 0.0.0.0
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", LISTEN_PORT))
            _dns_sockets.append(s)
            logger.info(f"[DNS_SERVER] Fallback bound to 0.0.0.0:{LISTEN_PORT}")
        except Exception as exc:
            logger.error(f"[DNS_SERVER] Total bind failure: {exc}")
            _dns_server_running = False
            return

    logger.info(f"[DNS_SERVER] Live on {len(_dns_sockets)} socket(s) - Ready to log laptop, PC and phone traffic!")

    while _dns_server_running:
        try:
            readable, _, _ = select.select(_dns_sockets, [], [], 1.0)
            for sock in readable:
                try:
                    data, client_addr = sock.recvfrom(4096)
                    if not data:
                        continue
                    t = threading.Thread(
                        target=_handle_dns_query,
                        args=(data, client_addr, sock),
                        daemon=True,
                    )
                    t.start()
                except Exception as sock_err:
                    logger.debug(f"[DNS_SERVER] Socket recv error: {sock_err}")
        except Exception as exc:
            if _dns_server_running:
                logger.error(f"[DNS_SERVER] Loop error: {exc}")
            time.sleep(0.5)

    for s in _dns_sockets:
        try:
            s.close()
        except Exception:
            pass
    _dns_sockets = []


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
    global _dns_server_running, _dns_sockets
    _dns_server_running = False
    for s in _dns_sockets:
        try:
            s.close()
        except Exception:
            pass
    _dns_sockets = []
