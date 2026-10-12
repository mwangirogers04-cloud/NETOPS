
from fastapi import APIRouter, Depends, Query
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
    event_type: str | None = Query(default=None, min_length=1),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    query = select(Event)

    if event_type is not None:
        query = query.where(Event.event_type == event_type)

    query = (
        query
        .order_by(Event.id.desc())
        .offset(offset)
        .limit(limit)
    )

    events = db.scalars(query).all()

    return events
