import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, or_
from ..database import SessionLocal
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


            for key, report in latest_by_endpoint.items():
                if not report.last_checked:
                    continue

                last_checked = get_naive_utc(report.last_checked)
                is_stale = last_checked < cutoff


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
                            f"Endpoint {report.hostname} is reporting again. "
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
