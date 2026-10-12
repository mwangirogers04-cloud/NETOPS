from datetime import datetime, time

from sqlalchemy.orm import Session

from ..models.access_schedule import AccessSchedule


def is_access_allowed(
    db: Session,
    device_id: int,
    current_time: time | None = None,
    current_datetime: datetime | None = None,
) -> bool:
    """
    Determine whether Internet access should currently be allowed
    for a device based on its active access schedule.

    This function only makes the access decision.
    It does NOT change the firewall or network configuration.
    """

    if current_datetime is None:
        current_datetime = datetime.now()

    if current_time is None:
        current_time = current_datetime.time()

    schedules = (
        db.query(AccessSchedule)
        .filter(
            AccessSchedule.device_id == device_id,
            AccessSchedule.enabled.is_(True),
        )
        .all()
    )

    if not schedules:
        return True

    current_day = current_datetime.strftime("%A").lower()

    for schedule in schedules:
        days = schedule.days.lower().strip()

        if days == "daily":
            day_matches = True
        else:
            configured_days = [
                day.strip()
                for day in days.split(",")
            ]

            day_matches = current_day in configured_days

        if not day_matches:
            continue

        start = schedule.start_time
        end = schedule.end_time

        # Normal schedule, e.g. 08:00 -> 17:00
        if start <= end:
            if start <= current_time <= end:
                return True

        # Overnight schedule, e.g. 22:00 -> 06:00
        else:
            if current_time >= start or current_time <= end:
                return True

    return False
