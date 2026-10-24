import asyncio
from datetime import datetime

from sqlalchemy import select

from ..database import SessionLocal
from ..models.device import Device
from .l2_quarantine import quarantine_device_l2
from .network_enforcement import enforce_device_access


SCHEDULE_CHECK_INTERVAL = 3


async def schedule_enforcement_loop():
    """
    Automatically evaluate access schedules and maintain Layer 2 / Firewall
    quarantine for all online quarantined or isolated devices (including Wi-Fi wlan0).

    The loop checks every 3 seconds and re-runs the existing
    network enforcement logic. This allows scheduled access to
    change automatically when a schedule opens or expires.
    """

    while True:
        db = SessionLocal()

        try:
            devices = db.scalars(
                select(Device).order_by(Device.id)
            ).all()

            current_datetime = datetime.now()
            quarantined_online_targets: list[tuple[str, str, str | None]] = []

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
            db.close()

        for _ in range(SCHEDULE_CHECK_INTERVAL):
            await asyncio.sleep(1)
            for ip_addr, mac_addr, clean_iface in quarantined_online_targets:
                try:
                    quarantine_device_l2(ip_addr, mac_addr, burst=1, interface=clean_iface)
                except Exception:
                    pass
