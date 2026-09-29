from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.event import Event


router = APIRouter(
    prefix="/events",
    tags=["Events"],
)


@router.get("/")
def get_events(
    db: Session = Depends(get_db),
):
    events = db.scalars(
        select(Event).order_by(Event.id.desc())
    ).all()

    return events

