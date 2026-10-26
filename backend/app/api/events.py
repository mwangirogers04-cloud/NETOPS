from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.event import Event
from ..models.user import User
from ..services.auth_service import require_super_admin


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


@router.delete("/clear")
def clear_events(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    """
    Clear/purge audit logs and event history.
    Strictly restricted to Super Administrator (Developer).
    Standard administrators and users are strictly forbidden.
    """
    db.execute(delete(Event))
    db.commit()
    return {"status": "cleared", "message": "All audit event logs have been cleared by Super Administrator."}


@router.delete("/{event_id}")
def delete_single_event(
    event_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    """
    Delete a single audit log event.
    Strictly restricted to Super Administrator (Developer).
    """
    event = db.get(Event, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event log not found.")
    db.delete(event)
    db.commit()
    return {"status": "deleted", "message": f"Event #{event_id} removed by Super Administrator."}
