from datetime import datetime, time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.access_schedule import AccessSchedule
from ..models.device import Device
from ..services.access_schedule import is_access_allowed
from ..services.network_enforcement import enforce_device_access

router = APIRouter(
    prefix="/access-schedules",
    tags=["Access Schedules"],
)


class AccessScheduleCreate(BaseModel):
    device_id: int
    enabled: bool = True
    start_time: time
    end_time: time
    days: str = "daily"


class AccessScheduleResponse(BaseModel):
    id: int
    device_id: int
    enabled: bool
    start_time: time
    end_time: time
    days: str

    class Config:
        from_attributes = True


@router.post("/", response_model=AccessScheduleResponse)
def create_access_schedule(
    schedule: AccessScheduleCreate,
    db: Session = Depends(get_db),
):
    device = db.get(Device, schedule.device_id)

    if not device:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    now = datetime.now()
    new_schedule = AccessSchedule(
        device_id=schedule.device_id,
        enabled=schedule.enabled,
        start_time=schedule.start_time,
        end_time=schedule.end_time,
        days=schedule.days,
        created_at=now,
        updated_at=now,
    )

    db.add(new_schedule)
    db.commit()
    db.refresh(new_schedule)

    # Immediately evaluate and enforce on firewall and network
    enforce_device_access(
        device,
        db,
        force=True,
    )
    db.commit()

    return new_schedule


@router.get("/", response_model=list[AccessScheduleResponse])
def get_access_schedules(
    db: Session = Depends(get_db),
):
    schedules = (
        db.query(AccessSchedule)
        .order_by(AccessSchedule.id.desc())
        .all()
    )

    return schedules


@router.get("/{schedule_id}", response_model=AccessScheduleResponse)
def get_access_schedule(
    schedule_id: int,
    db: Session = Depends(get_db),
):
    schedule = db.get(AccessSchedule, schedule_id)

    if not schedule:
        raise HTTPException(
            status_code=404,
            detail="Access schedule not found",
        )

    return schedule


@router.put("/{schedule_id}", response_model=AccessScheduleResponse)
def update_access_schedule(
    schedule_id: int,
    schedule_data: AccessScheduleCreate,
    db: Session = Depends(get_db),
):
    schedule = db.get(AccessSchedule, schedule_id)

    if not schedule:
        raise HTTPException(
            status_code=404,
            detail="Access schedule not found",
        )

    device = db.get(Device, schedule_data.device_id)

    if not device:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    schedule.device_id = schedule_data.device_id
    schedule.enabled = schedule_data.enabled
    schedule.start_time = schedule_data.start_time
    schedule.end_time = schedule_data.end_time
    schedule.days = schedule_data.days
    schedule.updated_at = datetime.now()

    db.commit()
    db.refresh(schedule)

    # Immediately evaluate and enforce on firewall and network
    enforce_device_access(
        device,
        db,
        force=True,
    )
    db.commit()

    return schedule


@router.delete("/{schedule_id}")
def delete_access_schedule(
    schedule_id: int,
    db: Session = Depends(get_db),
):
    schedule = db.get(AccessSchedule, schedule_id)

    if not schedule:
        raise HTTPException(
            status_code=404,
            detail="Access schedule not found",
        )

    device_id = schedule.device_id
    device = db.get(Device, device_id)

    db.delete(schedule)
    db.commit()

    if device:
        enforce_device_access(
            device,
            db,
            force=True,
        )
        db.commit()

    return {
        "message": "Access schedule deleted successfully",
        "schedule_id": schedule_id,
    }

@router.get("/device/{device_id}/decision")
def get_device_access_decision(
    device_id: int,
    db: Session = Depends(get_db),
):
    device = db.get(Device, device_id)

    if not device:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )

    allowed = is_access_allowed(db, device_id)

    return {
        "device_id": device_id,
        "access_allowed": allowed,
        "checked_at": datetime.now().isoformat(),
    }
