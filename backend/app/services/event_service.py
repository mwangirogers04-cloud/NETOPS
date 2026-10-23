from sqlalchemy.orm import Session

from ..models.event import Event


def create_event(
    db: Session,
    event_type: str,
    message: str,
    device_id: int | None = None,
    actor: str | None = None,
):
    """
    Create an audit event within the caller's transaction.

    The function intentionally does NOT commit the database
    transaction. The caller is responsible for committing or
    rolling back the transaction.

    This allows larger NETOPS operations to remain atomic.
    """

    event = Event(
        event_type=event_type,
        message=message,
        device_id=device_id,
        actor=actor,
    )

    db.add(event)
    db.flush()

    return event
