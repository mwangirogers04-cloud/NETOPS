import logging
import os
import re
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from sqlalchemy import func, select, desc
from sqlalchemy.orm import Session

from ..database import SessionLocal
from ..models.device import Device
from ..models.event import Event
from ..models.web_activity import WebActivityLog, WebFilterPolicy
from .web_categorizer import categorize_domain, clean_domain, is_prohibited_during_work
from .websocket_manager import manager

logger = logging.getLogger(__name__)

# Global sniffer process control
_sniffer_process: subprocess.Popen | None = None
_sniffer_thread: threading.Thread | None = None
_sniffer_running: bool = False
_sniffer_lock = threading.Lock()

# In-memory aggregation buffer: (client_ip, domain) -> {hit_count, last_logged, log_id}
_recent_hits_buffer: dict[tuple[str, str], float] = {}
_buffer_lock = threading.Lock()


def get_or_create_web_policy(db: Session) -> WebFilterPolicy:
    """Retrieve or initialize the system-wide web filter policy."""
    policy = db.scalars(select(WebFilterPolicy)).first()
    if not policy:
        policy = WebFilterPolicy(
            block_streaming_work_hours=True,
            block_gaming_work_hours=True,
            block_social_media_work_hours=False,
            block_adult_always=True,
            enforce_schedule=True,
            sniffer_enabled=True,
        )
        db.add(policy)
        db.commit()
        db.refresh(policy)
    return policy


def _is_working_hours_now() -> bool:
    """Check if current local time falls into typical institution working hours (Mon-Fri 08:00 - 17:00)."""
    now = datetime.now()
    if now.weekday() >= 5:  # Saturday or Sunday
        return False
    return 8 <= now.hour < 17


def record_web_activity(
    db: Session,
    ip_address: str,
    domain: str,
    protocol: str = "DNS",
    custom_timestamp: datetime | None = None,
) -> WebActivityLog | None:
    """
    Record and classify a web activity visit by an endpoint.
    Aggregates repeat hits within a 30-second window.
    """
    clean_d = clean_domain(domain)
    if not clean_d or "." not in clean_d or clean_d.endswith(".arpa") or clean_d.endswith(".local"):
        return None

    client_ip = (ip_address or "").strip()
    if not client_ip or client_ip in ("127.0.0.1", "::1"):
        return None

    # Deduplication throttling: ignore repeated hits for exact same IP + domain within 20s
    buf_key = (client_ip, clean_d)
    now_ts = time.time()
    with _buffer_lock:
        last_ts = _recent_hits_buffer.get(buf_key, 0)
        if now_ts - last_ts < 20:
            return None
        _recent_hits_buffer[buf_key] = now_ts
        # Purge old entries
        if len(_recent_hits_buffer) > 2000:
            cutoff = now_ts - 120
            _recent_hits_buffer.clear()

    # Correlate client device
    device = db.scalars(select(Device).where(Device.ip_address == client_ip)).first()
    dev_id = device.id if device else None
    dev_host = (device.hostname if device else None) or f"HOST-{client_ip.replace('.', '-')}"
    dev_mac = device.mac_address if device else None

    # Classify domain
    category = categorize_domain(clean_d)

    # Evaluate working hours policy
    in_work_hours = _is_working_hours_now()
    policy = get_or_create_web_policy(db)
    policy_dict = {
        "block_streaming_work_hours": policy.block_streaming_work_hours,
        "block_gaming_work_hours": policy.block_gaming_work_hours,
        "block_social_media_work_hours": policy.block_social_media_work_hours,
        "block_adult_always": policy.block_adult_always,
    }

    is_violation = False
    action = "monitored"
    if in_work_hours or category == "gambling_adult":
        if is_prohibited_during_work(category, policy_dict):
            is_violation = True
            action = "flagged"

    entry = WebActivityLog(
        device_id=dev_id,
        ip_address=client_ip,
        mac_address=dev_mac,
        hostname=dev_host,
        domain=clean_d,
        category=category,
        protocol=protocol,
        is_violation=is_violation,
        action=action,
        hit_count=1,
        timestamp=custom_timestamp or datetime.now(timezone.utc),
    )
    db.add(entry)

    # Record event if prohibited activity detected
    if is_violation:
        evt_type = f"prohibited_{category}"
        cat_title = category.replace("_", " ").title()
        db.add(
            Event(
                device_id=dev_id,
                event_type=evt_type,
                message=f"⚠️ {dev_host} ({client_ip}) accessed {cat_title} site: {clean_d} during working hours.",
            )
        )

    db.commit()
    db.refresh(entry)

    # Broadcast event via WebSockets if event loop is active
    try:
        import asyncio
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.run_coroutine_threadsafe(
                manager.broadcast({
                    "type": "web_activity",
                    "data": {
                        "id": entry.id,
                        "ip_address": entry.ip_address,
                        "hostname": entry.hostname,
                        "domain": entry.domain,
                        "category": entry.category,
                        "is_violation": entry.is_violation,
                        "action": entry.action,
                        "timestamp": entry.timestamp.isoformat(),
                    }
                }),
                loop,
            )
    except Exception:
        pass

    return entry


def _sniffer_loop():
    """Background loop reading live DNS packets via tcpdump."""
    global _sniffer_process, _sniffer_running
    logger.info("[WEB_SNIFFER] Starting live passive DNS capture...")

    # Pattern matches standard tcpdump DNS A/AAAA/HTTPS queries with or without EDNS flags:
    # IP 192.168.0.104.54321 > 192.168.0.1.53: 1234+ [1au] A? youtube.com. (39)
    dns_pattern = re.compile(
        r"IP\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+\s*>\s*[0-9\.]+\.53:\s+.*?(?:A|AAAA|HTTPS)\?\s+([a-zA-Z0-9\-\.\_]+)\."
    )

    cmd = ["sudo", "-n", "tcpdump", "-l", "-n", "-i", "any", "udp dst port 53"]

    while _sniffer_running:
        try:
            _sniffer_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )

            for line in iter(_sniffer_process.stdout.readline, ""):
                if not _sniffer_running:
                    break
                if not line:
                    continue

                match = dns_pattern.search(line)
                if match:
                    src_ip = match.group(1)
                    raw_domain = match.group(2)

                    # Filter out local DNS queries to standard resolvers or Kali itself
                    if raw_domain and not raw_domain.endswith(".arpa") and not raw_domain.endswith(".local"):
                        try:
                            with SessionLocal() as db:
                                record_web_activity(db, src_ip, raw_domain, protocol="DNS")
                        except Exception as exc:
                            logger.error(f"[WEB_SNIFFER] Error recording web activity: {exc}")

            if _sniffer_process:
                _sniffer_process.poll()

        except Exception as exc:
            logger.error(f"[WEB_SNIFFER] Sniffer error: {exc}")
            time.sleep(3)


def start_web_traffic_sniffer():
    """Start passive DNS traffic sniffer thread if enabled."""
    global _sniffer_thread, _sniffer_running
    with _sniffer_lock:
        if _sniffer_running:
            return
        _sniffer_running = True
        _sniffer_thread = threading.Thread(
            target=_sniffer_loop,
            daemon=True,
            name="web-traffic-sniffer",
        )
        _sniffer_thread.start()
        logger.info("[WEB_SNIFFER] Thread launched successfully.")


def stop_web_traffic_sniffer():
    """Stop live passive DNS capture."""
    global _sniffer_process, _sniffer_running
    with _sniffer_lock:
        _sniffer_running = False
        if _sniffer_process:
            try:
                _sniffer_process.terminate()
            except Exception:
                pass
            _sniffer_process = None


def get_web_activity_analytics(db: Session, hours: int = 24) -> dict:
    """Generate aggregated web activity statistics for the dashboard."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    # Base query for the time window
    base_q = select(WebActivityLog).where(WebActivityLog.timestamp >= cutoff)
    all_logs = db.scalars(base_q).all()

    total_queries = len(all_logs)
    category_counts = defaultdict(int)
    streaming_devices = defaultdict(int)
    gaming_devices = defaultdict(int)
    social_devices = defaultdict(int)
    domain_counts = defaultdict(int)
    violations_count = 0

    for log in all_logs:
        category_counts[log.category] += 1
        domain_counts[log.domain] += 1
        if log.is_violation:
            violations_count += 1

        dev_name = log.hostname or log.ip_address
        if log.category == "streaming":
            streaming_devices[dev_name] += 1
        elif log.category == "gaming":
            gaming_devices[dev_name] += 1
        elif log.category == "social_media":
            social_devices[dev_name] += 1

    top_streaming = [
        {"device": k, "hits": v}
        for k, v in sorted(streaming_devices.items(), key=lambda x: x[1], reverse=True)[:5]
    ]

    top_gaming = [
        {"device": k, "hits": v}
        for k, v in sorted(gaming_devices.items(), key=lambda x: x[1], reverse=True)[:5]
    ]

    top_social = [
        {"device": k, "hits": v}
        for k, v in sorted(social_devices.items(), key=lambda x: x[1], reverse=True)[:5]
    ]

    top_domains = [
        {"domain": k, "hits": v, "category": categorize_domain(k)}
        for k, v in sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    ]

    return {
        "time_window_hours": hours,
        "total_queries": total_queries,
        "violations_count": violations_count,
        "category_counts": dict(category_counts),
        "top_streaming_devices": top_streaming,
        "top_gaming_devices": top_gaming,
        "top_social_devices": top_social,
        "top_domains": top_domains,
    }


def get_active_web_sessions(db: Session, minutes: int = 5) -> list[dict]:
    """
    Returns devices and domains actively communicating within the last `minutes`.
    If a user has left the site (no traffic within `minutes`), they are omitted.
    Groups by (ip_address, domain).
    """
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=minutes)
    q = (
        select(WebActivityLog)
        .where(WebActivityLog.timestamp >= cutoff)
        .order_by(desc(WebActivityLog.timestamp))
    )
    recent_logs = db.scalars(q).all()
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    sessions: dict[tuple[str, str], dict] = {}
    for log in recent_logs:
        log_time = log.timestamp
        if log_time.tzinfo is not None:
            log_time = log_time.replace(tzinfo=None)

        key = (log.ip_address, log.domain)
        if key not in sessions:
            seconds_ago = max(0, int((now - log_time).total_seconds()))
            status = "active" if seconds_ago < 120 else "idle"
            sessions[key] = {
                "id": log.id,
                "device_id": log.device_id,
                "ip_address": log.ip_address,
                "mac_address": log.mac_address,
                "hostname": log.hostname or log.ip_address,
                "domain": log.domain,
                "category": log.category,
                "protocol": log.protocol,
                "is_violation": log.is_violation,
                "action": log.action,
                "hit_count": log.hit_count,
                "last_seen": log.timestamp.isoformat(),
                "seconds_ago": seconds_ago,
                "status": status,
            }
        else:
            sessions[key]["hit_count"] += log.hit_count

    return sorted(list(sessions.values()), key=lambda s: s["seconds_ago"])

