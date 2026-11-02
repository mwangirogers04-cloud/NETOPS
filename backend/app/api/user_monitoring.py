from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.user import User
from ..services.auth_service import require_admin
from ..services.user_monitoring_service import (
    get_user_monitoring_summary,
    get_live_active_sessions,
    get_users_lifecycle_overview,
    get_sessions_history,
    terminate_session,
    terminate_all_user_sessions,
)

router = APIRouter(prefix="/user-monitoring", tags=["User Monitoring & Live Activity"])


@router.get("/summary")
def read_monitoring_summary(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Returns high-level statistics for online users, total registered accounts,
    sessions logged today, and total historical sessions.
    """
    return get_user_monitoring_summary(db)


@router.get("/live-sessions")
def read_live_sessions(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Returns users currently online and active on the platform,
    including current page, IP address, device, login timestamp, and duration.
    """
    return get_live_active_sessions(db)


@router.get("/users-overview")
def read_users_overview(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Returns user directory with first seen, last seen, online status,
    total login counts, and total time spent.
    """
    return get_users_lifecycle_overview(db)


@router.get("/sessions-history")
def read_sessions_history(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    search: str | None = Query(None),
    status_filter: str = Query("all", pattern="^(all|online|active|ended)$"),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Returns paginated access sessions audit log with filter by status or username.
    """
    return get_sessions_history(
        db=db,
        limit=limit,
        offset=offset,
        search=search,
        status_filter=status_filter,
    )


@router.post("/terminate-session/{session_id}")
def terminate_user_session_endpoint(
    session_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Forcibly terminate an active user session.
    """
    success = terminate_session(db, session_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or already closed.",
        )
    return {"status": "ok", "message": f"Session {session_id} has been terminated."}


@router.post("/terminate-user/{user_id}")
def terminate_all_sessions_for_user_endpoint(
    user_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Forcibly terminate all active sessions for a target user.
    """
    count = terminate_all_user_sessions(db, user_id)
    return {"status": "ok", "message": f"Terminated {count} active session(s) for user ID {user_id}."}
