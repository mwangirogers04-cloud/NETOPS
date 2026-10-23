from datetime import datetime, time, timedelta

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
        ct = current_datetime.time()
        current_time = time(ct.hour, ct.minute, ct.second)

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
        elif days == "weekdays":
            day_matches = current_day in {"monday", "tuesday", "wednesday", "thursday", "friday"}
        elif days == "weekends":
            day_matches = current_day in {"saturday", "sunday"}
        else:
            configured_days = [
                day.strip()
                for day in days.split(",")
            ]

            day_matches = current_day in configured_days

        if not day_matches:
            continue

        start = schedule.start_time
        start = time(start.hour, start.minute, start.second)
        end = schedule.end_time
        end = time(end.hour, end.minute, end.second)

        # 1. Standard active window check
        if start <= end:
            if start <= current_time <= end:
                return True
        else:
            if current_time >= start or current_time <= end:
                return True

        # 2. When a device is scheduled, it remains scheduled with access until that
        # scheduled access window ends for the first time.
        # For example, if scheduled right now at 20:55 to 21:00, it should be scheduled and
        # NOT go to quarantine until 21:01 reaches. At 21:01 it goes to quarantine until the
        # next day at 20:55 when it comes out of quarantine.
        sched_ref_time = getattr(schedule, "updated_at", None) or getattr(schedule, "created_at", None)
        if sched_ref_time:
            if sched_ref_time.tzinfo is not None:
                sched_ref_time = sched_ref_time.replace(tzinfo=None)
            curr_dt_naive = current_datetime.replace(tzinfo=None) if current_datetime.tzinfo else current_datetime

            sched_date = sched_ref_time.date()
            if start <= end:
                first_cutoff = datetime.combine(sched_date, end)
                if sched_ref_time <= first_cutoff and curr_dt_naive <= first_cutoff:
                    return True
            else:
                first_cutoff = datetime.combine(sched_date + timedelta(days=1), end)
                if sched_ref_time <= first_cutoff and curr_dt_naive <= first_cutoff:
                    return True

    return False
