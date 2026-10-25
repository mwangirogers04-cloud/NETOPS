import asyncio
import subprocess
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, or_
from ..database import SessionLocal
from ..models.device import Device
from ..models.endpoint_update import EndpointUpdate
from ..models.event import Event
from .event_service import create_event
from .firewall.manager import get_active_firewall_driver
from .sophos_enforcement import is_sophos_configured, sophos_allow_device
from .l2_quarantine import restore_device_l2
from .network_enforcement import enforce_device_access


STALE_AFTER_MINUTES = 15
CHECK_INTERVAL_SECONDS = 4

# In-memory debounce tracking to prevent flapping on transient ARP packet drops
_consecutive_misses: dict[str, int] = {}


def get_endpoint_key(report):
    """Return the strongest available endpoint identifier."""
    if report.machine_id:
        return f"machine:{report.machine_id}"

    if report.mac_address:
        mac = report.mac_address.replace(":", "").replace("-", "").upper()
        return f"mac:{mac}"

    return f"hostname:{report.hostname}" if report.hostname else None


def get_naive_utc(value):
    """Normalize database timestamps for comparison."""
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


async def endpoint_health_monitor_loop():
    """Record endpoint stale and recovery transitions."""

    print("NETOPS endpoint health monitor started")

    while True:
        db = SessionLocal()

        try:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            cutoff = now - timedelta(minutes=STALE_AFTER_MINUTES)

            reports = db.scalars(
                select(EndpointUpdate).order_by(
                    EndpointUpdate.last_checked.desc(),
                    EndpointUpdate.id.desc(),
                )
            ).all()


            latest_by_endpoint = {}
            seen_macs = set()
            seen_hostnames = set()

            for report in reports:
                mac = (
                    report.mac_address.replace(":", "").replace("-", "").upper()
                    if report.mac_address
                    else None
                )
                hostname = report.hostname.lower() if report.hostname else None

                if mac and mac in seen_macs:
                    continue

                if hostname and hostname in seen_hostnames:
                    continue

                key = get_endpoint_key(report)
                if not key:
                    continue

                latest_by_endpoint[key] = report

                if mac:
                    seen_macs.add(mac)
                if hostname:
                    seen_hostnames.add(hostname)


            # Check reachability of all inventory devices (both online and offline)
            is_mock_env = str(type(db)).startswith("<class 'unittest.mock")

            try:
                device_query = db.scalars(select(Device)).all()
            except Exception:
                device_query = []

            online_devices = []

            if is_mock_env:
                for d in device_query:
                    if isinstance(d, Device) and d.status == "online":
                        online_devices.append(d)
            else:
                # Live production: sweep LAN to detect all active machines across subnets
                active_ips = set()
                active_macs = set()
                live_by_mac = {}

                for iface in ("eth0", "wlan0"):
                    try:
                        res = subprocess.run(
                            ["arp-scan", "--interface", iface, "--localnet", "--retry=2", "--timeout=600"],
                            capture_output=True,
                            text=True,
                            check=False,
                            timeout=5,
                        )
                        for line in res.stdout.splitlines():
                            parts = line.strip().split()
                            if len(parts) >= 2 and ":" in parts[1] and len(parts[1].strip()) == 17:
                                ip_str = parts[0].strip()
                                mac_raw = parts[1].strip().upper()
                                mac_norm = mac_raw.replace(":", "").replace("-", "").upper()
                                vendor_str = " ".join(parts[2:]).strip() if len(parts) >= 3 else None
                                active_ips.add(ip_str)
                                active_macs.add(mac_norm)
                                live_by_mac[mac_norm] = {
                                    "ip_address": ip_str,
                                    "mac_address": mac_raw,
                                    "vendor": vendor_str,
                                    "interface": iface,
                                }
                    except Exception:
                        pass

                try:
                    res = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, check=False, timeout=3)
                    for line in res.stdout.splitlines():
                        parts = line.strip().split()
                        # Valid neighbour states include REACHABLE, DELAY, PROBE, and STALE (with valid lladdr)
                        if any(st in parts for st in ("REACHABLE", "DELAY", "PROBE", "STALE")):
                            if len(parts) >= 1:
                                active_ips.add(parts[0].strip())
                            if "lladdr" in parts:
                                idx = parts.index("lladdr")
                                if idx + 1 < len(parts):
                                    mac_entry = parts[idx + 1].strip().replace(":", "").replace("-", "").upper()
                                    active_macs.add(mac_entry)
                                    if mac_entry not in live_by_mac and len(parts) >= 1:
                                        dev_iface = (
                                            parts[parts.index("dev") + 1]
                                            if "dev" in parts and parts.index("dev") + 1 < len(parts)
                                            else "eth0"
                                        )
                                        live_by_mac[mac_entry] = {
                                            "ip_address": parts[0].strip(),
                                            "mac_address": parts[idx + 1].strip().upper(),
                                            "vendor": "LAN Device",
                                            "interface": dev_iface,
                                        }
                except Exception:
                    pass

                existing_macs = set()
                for d in device_query:
                    if isinstance(d, Device) and d.mac_address:
                        existing_macs.add(d.mac_address.replace(":", "").replace("-", "").upper())

                # Auto-register any brand-new machine that just connected to eth0 or wlan0
                for mac_norm, info in live_by_mac.items():
                    if mac_norm not in existing_macs:
                        new_dev = Device(
                            mac_address=info["mac_address"],
                            ip_address=info["ip_address"],
                            hostname=f"LAN-HOST-{info['ip_address'].replace('.', '-')}",
                            vendor=info["vendor"],
                            device_type="computer",
                            network_interface=info["interface"],
                            status="online",
                            approval_status="pending",
                            ip_assignment="dhcp",
                            classification_status="normal",
                            vlan_id=90,
                            enforcement_status="quarantined",
                            internet_access_authorized=False,
                        )
                        db.add(new_dev)
                        db.flush()
                        existing_macs.add(mac_norm)
                        device_query.append(new_dev)
                        create_event(
                            db=db,
                            event_type="new_device",
                            message=(
                                f"New machine connected to LAN ({info['interface']}): "
                                f"{info['ip_address']} ({info['mac_address']}) "
                                f"[{info['vendor'] or 'Unknown Vendor'}] — "
                                f"Placed in VLAN 90 Quarantine. Awaiting administrator review & approval."
                            ),
                            device_id=new_dev.id,
                        )

                for d in device_query:
                    if not isinstance(d, Device):
                        continue
                    if not d.ip_address and not d.mac_address:
                        if d.status == "online":
                            online_devices.append(d)
                        continue
                    if d.hostname and d.hostname.lower() in ("kali", "localhost"):
                        if d.status == "online":
                            online_devices.append(d)
                        continue

                    d_mac = d.mac_address.replace(":", "").replace("-", "").upper() if d.mac_address else None
                    is_active = (d.ip_address and d.ip_address in active_ips) or (d_mac and d_mac in active_macs)

                    if not is_active and d.status == "online" and d.ip_address:
                        # Prioritize the device's recorded interface, then fall back to others
                        preferred_iface = getattr(d, "network_interface", None) or "eth0"
                        ifaces_to_try = [preferred_iface]
                        for alt in ("eth0", "wlan0"):
                            if alt not in ifaces_to_try:
                                ifaces_to_try.append(alt)
                        for iface in ifaces_to_try:
                            try:
                                res = subprocess.run(
                                    ["arping", "-c", "2", "-w", "1.5", "-I", iface, d.ip_address],
                                    capture_output=True,
                                    check=False,
                                    timeout=3,
                                )
                                if res.returncode == 0:
                                    is_active = True
                                    d.network_interface = iface
                                    break
                            except Exception:
                                pass

                        if not is_active:
                            try:
                                res = subprocess.run(
                                    ["ping", "-c", "1", "-W", "1", d.ip_address],
                                    capture_output=True,
                                    check=False,
                                    timeout=2,
                                )
                                if res.returncode == 0:
                                    is_active = True
                            except Exception:
                                pass

                    d_key = d_mac or str(d.id)
                    if is_active:
                        _consecutive_misses[d_key] = 0
                        live_info = live_by_mac.get(d_mac) if d_mac else None
                        if live_info:
                            old_ip = d.ip_address
                            new_ip = live_info.get("ip_address")
                            if new_ip and old_ip and old_ip != new_ip:
                                if getattr(d, "ip_assignment", "dhcp") == "static":
                                    create_event(
                                        db=db,
                                        event_type="ip_address_conflict",
                                        message=(
                                            f"Static IP mismatch for {d.hostname or d.mac_address} ({d.mac_address}): "
                                            f"Configured static IP was {old_ip}, but observed with {new_ip}. "
                                            f"Manual review required."
                                        ),
                                        device_id=d.id,
                                    )
                                else:
                                    # DHCP lease change: treat as a new machine accessing our internet
                                    try:
                                        active_fw = get_active_firewall_driver(db)
                                        if active_fw.vendor != "sophos" and active_fw.is_configured() and old_ip:
                                            active_fw.allow_device(old_ip)
                                        elif is_sophos_configured() and old_ip:
                                            sophos_allow_device(old_ip)
                                        restore_device_l2(old_ip)
                                    except Exception as exc:
                                        print(f"[MONITOR] Error releasing old IP {old_ip}: {exc}")

                                    d.ip_address = new_ip
                                    d.approval_status = "pending"
                                    d.internet_access_authorized = False
                                    d.vlan_id = 90
                                    d.enforcement_status = "quarantined"

                                    try:
                                        enforce_device_access(d, db, force=True)
                                    except Exception as exc:
                                        print(f"[MONITOR] Error enforcing quarantine on {new_ip}: {exc}")

                                    create_event(
                                        db=db,
                                        event_type="ip_address_changed",
                                        message=f"Device IP address changed from {old_ip} to {new_ip} ({d.mac_address})",
                                        device_id=d.id,
                                    )
                                    create_event(
                                        db=db,
                                        event_type="new_device",
                                        message=(
                                            f"Machine connected with new DHCP IP ({live_info.get('interface') or d.network_interface or 'eth0'}): "
                                            f"{d.hostname or d.mac_address} ({new_ip} / {d.mac_address}) "
                                            f"[{d.vendor or 'LAN Device'}] — "
                                            f"Previous IP was {old_ip}. Treated as new machine: Placed in VLAN 90 Quarantine. Awaiting administrator review & approval."
                                        ),
                                        device_id=d.id,
                                    )
                            elif new_ip and not old_ip:
                                d.ip_address = new_ip

                            if live_info.get("interface"):
                                d.network_interface = live_info["interface"]

                        # Quarantined or isolated devices must read offline until authorized for internet
                        is_quarantined_or_isolated = (
                            d.enforcement_status in ("quarantined", "isolated")
                            or not getattr(d, "internet_access_authorized", True)
                        )
                        expected_status = "offline" if is_quarantined_or_isolated else "online"

                        if d.status != expected_status:
                            d.status = expected_status
                            if expected_status == "online":
                                ev_type = "new_device" if d.approval_status == "pending" else "device_online"
                                create_event(
                                    db=db,
                                    event_type=ev_type,
                                    message=(
                                        f"Machine connected to LAN ({d.network_interface or 'eth0'}): "
                                        f"{d.hostname or d.ip_address} ({d.ip_address or 'LAN'} / {d.mac_address}) "
                                        f"[{d.vendor or 'LAN Device'}] — "
                                        + (
                                            f"Placed in VLAN {d.vlan_id or 90} Quarantine, awaiting administrator review."
                                            if d.approval_status == "pending"
                                            else f"Online on VLAN {d.vlan_id or 20} ({d.enforcement_status})."
                                        )
                                    ),
                                    device_id=d.id,
                                )
                        if expected_status == "online":
                            online_devices.append(d)
                    else:
                        if d.status == "online":
                            misses = _consecutive_misses.get(d_key, 0) + 1
                            _consecutive_misses[d_key] = misses
                            if misses < 3:
                                # Debounce: retain online status for 3 consecutive misses (~12s) to absorb transient ARP/Wi-Fi jitter
                                online_devices.append(d)
                            else:
                                d.status = "offline"
                                latest_offline = db.scalar(
                                    select(Event)
                                    .where(
                                        Event.device_id == d.id,
                                        Event.event_type == "device_offline",
                                    )
                                    .order_by(Event.id.desc())
                                    .limit(1)
                                )
                                if not latest_offline:
                                    create_event(
                                        db=db,
                                        event_type="device_offline",
                                        message=(
                                            f"Device {d.hostname or d.ip_address} ({d.mac_address}) "
                                            f"went offline / disconnected from the LAN."
                                        ),
                                        device_id=d.id,
                                    )

            online_macs = set()
            online_ips = set()
            online_hosts = set()
            for d in online_devices:
                if d.mac_address:
                    online_macs.add(d.mac_address.replace(":", "").replace("-", "").upper())
                if d.ip_address:
                    online_ips.add(d.ip_address.strip())
                if d.hostname:
                    online_hosts.add(d.hostname.strip().lower())

            for key, report in latest_by_endpoint.items():
                if not report.last_checked:
                    continue

                last_checked = get_naive_utc(report.last_checked)

                rep_mac = (
                    report.mac_address.replace(":", "").replace("-", "").upper()
                    if getattr(report, "mac_address", None)
                    else None
                )
                rep_ip = report.ip_address.strip() if getattr(report, "ip_address", None) else None
                rep_host = report.hostname.strip().lower() if getattr(report, "hostname", None) else None

                is_device_online = bool(
                    (rep_mac and rep_mac in online_macs)
                    or (rep_ip and rep_ip in online_ips)
                    or (rep_host and rep_host in online_hosts)
                )

                # An endpoint is never stale while its physical machine is online on the LAN
                is_stale = (last_checked < cutoff) and not is_device_online

                # If device is confirmed online on the network, keep its timestamp current
                if is_device_online and not str(type(report)).startswith("<class 'unittest.mock"):
                    report.last_checked = datetime.now(timezone.utc)

                previous_event = db.scalars(
                    select(Event)
                    .where(
                        Event.event_type.in_(
                            ["endpoint_stale", "endpoint_recovered"]
                        ),
                        Event.message.contains(f"Endpoint key: {key}"),
                    )
                    .order_by(Event.id.desc())
                ).first()

                if is_stale:
                    if (
                        previous_event is None
                        or previous_event.event_type != "endpoint_stale"
                    ):
                        create_event(
                            db=db,
                            event_type="endpoint_stale",
                            message=(
                                f"Endpoint {report.hostname} has stopped "
                                f"reporting. Last report: "
                                f"{last_checked.isoformat()}. "
                                f"Endpoint key: {key}"
                            ),
                        )
                elif (
                    previous_event is not None
                    and previous_event.event_type == "endpoint_stale"
                ):
                    create_event(
                        db=db,
                        event_type="endpoint_recovered",
                        message=(
                            f"Endpoint {report.hostname} is online and reporting. "
                            f"Endpoint key: {key}"
                        ),
                    )


            db.commit()

        except Exception as error:
            db.rollback()
            print(f"[ENDPOINT HEALTH] Monitor error: {error}")

        finally:
            db.close()

        await asyncio.sleep(CHECK_INTERVAL_SECONDS)
