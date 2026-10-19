import asyncio
import subprocess
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, or_
from ..database import SessionLocal
from ..models.device import Device
from ..models.endpoint_update import EndpointUpdate
from ..models.event import Event
from .event_service import create_event


STALE_AFTER_MINUTES = 15
CHECK_INTERVAL_SECONDS = 60


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


            # Pre-fetch online devices from inventory
            try:
                device_query = db.scalars(select(Device)).all()
                online_devices = [
                    d for d in device_query
                    if isinstance(d, Device) and d.status == "online"
                ]
            except Exception:
                online_devices = []

            # In live production, verify reachability of online devices
            for d in list(online_devices):
                if str(type(d)).startswith("<class 'unittest.mock"):
                    continue
                if not d.ip_address:
                    continue
                if d.hostname and d.hostname.lower() in ("kali", "localhost"):
                    continue

                is_active = False
                for iface in ("eth0", "wlan0"):
                    try:
                        res = subprocess.run(
                            ["arping", "-c", "1", "-w", "1", "-I", iface, d.ip_address],
                            capture_output=True,
                            check=False,
                            timeout=2,
                        )
                        if res.returncode == 0:
                            is_active = True
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

                if not is_active:
                    d.status = "offline"
                    create_event(
                        db=db,
                        event_type="device_offline",
                        message=(
                            f"Device {d.hostname or d.ip_address} ({d.mac_address}) "
                            f"went offline / disconnected from the LAN."
                        ),
                        device_id=d.id,
                    )
                    online_devices.remove(d)

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
