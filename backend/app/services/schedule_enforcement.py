import asyncio
from datetime import datetime

from sqlalchemy import select

from ..database import SessionLocal
from ..models.device import Device
from .l2_quarantine import quarantine_device_l2, clear_all_l2_quarantines, _is_cloud_host
from .network_enforcement import enforce_device_access


SCHEDULE_CHECK_INTERVAL = 3


def _run_schedule_enforcement_sync() -> list[tuple[str, str, str | None]]:
    """Synchronous worker that evaluates access schedules in a worker thread."""
    db = SessionLocal()
    quarantined_online_targets: list[tuple[str, str, str | None]] = []

    try:
        devices = db.scalars(
            select(Device).order_by(Device.id)
        ).all()

        try:
            import zoneinfo
            current_datetime = datetime.now(zoneinfo.ZoneInfo("Africa/Nairobi"))
        except Exception:
            current_datetime = datetime.now()

        for device in devices:
            try:
                enforce_device_access(
                    device,
                    db,
                    current_datetime=current_datetime,
                )
                db.commit()

                if (
                    device.ip_address
                    and device.mac_address
                    and device.enforcement_status in ("quarantined", "isolated")
                ):
                    dev_iface = getattr(device, "network_interface", None)
                    clean_iface = dev_iface if isinstance(dev_iface, str) else None
                    quarantined_online_targets.append(
                        (device.ip_address, device.mac_address, clean_iface)
                    )
                    if not _is_cloud_host():
                        quarantine_device_l2(
                            device.ip_address,
                            device.mac_address,
                            burst=2,
                            interface=clean_iface,
                        )
            except Exception as dev_err:
                db.rollback()
                print(
                    f"[SCHEDULE] Error enforcing device #{device.id}: {dev_err}"
                )

    except Exception as error:
        db.rollback()
        quarantined_online_targets = []
        print(
            f"[SCHEDULE] Automatic enforcement error: {error}"
        )

    finally:
        try:
            if db.is_active:
                db.rollback()
        except Exception:
            pass
        db.close()

    return quarantined_online_targets


async def schedule_enforcement_loop():
    """
    Automatically evaluate access schedules and maintain Layer 2 / Firewall
    quarantine for all online quarantined or isolated devices.
    Runs DB operations in a thread pool so the asyncio event loop remains non-blocking.
    """
    is_cloud = _is_cloud_host()

    while True:
        try:
            quarantined_targets = await asyncio.to_thread(_run_schedule_enforcement_sync)
        except Exception as exc:
            quarantined_targets = []

        interval = 15 if is_cloud else SCHEDULE_CHECK_INTERVAL
        if not is_cloud and not quarantined_targets:
            clear_all_l2_quarantines()
        for _ in range(interval):
            await asyncio.sleep(1)
            if not is_cloud and quarantined_targets:
                for ip_addr, mac_addr, clean_iface in quarantined_targets:
                    try:
                        quarantine_device_l2(ip_addr, mac_addr, burst=1, interface=clean_iface)
                    except Exception:
                        pass
