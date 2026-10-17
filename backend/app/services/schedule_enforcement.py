import asyncio
from datetime import datetime

from sqlalchemy import select

from ..database import SessionLocal
from ..models.device import Device
from .network_enforcement import enforce_device_access


SCHEDULE_CHECK_INTERVAL = 3


async def schedule_enforcement_loop():
    """
    Automatically evaluate access schedules for all devices.

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

            for device in devices:
                try:
                    enforce_device_access(
                        device,
                        db,
                        current_datetime=current_datetime,
                    )
                    db.commit()
                except Exception as dev_err:
                    db.rollback()
                    print(
                        f"[SCHEDULE] Error enforcing device #{device.id}: {dev_err}"
                    )

        except Exception as error:
            db.rollback()

            print(
                f"[SCHEDULE] Automatic enforcement error: {error}"
            )

        finally:
            db.close()

        await asyncio.sleep(
            SCHEDULE_CHECK_INTERVAL
        )
