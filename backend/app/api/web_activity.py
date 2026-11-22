from datetime import datetime, timezone, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.orm import Session

from ..database import get_db
from ..services.auth_service import require_admin, require_super_admin, get_optional_current_user
from ..models.device import Device
from ..models.user import User
from ..models.web_activity import WebActivityLog, WebFilterPolicy
from ..services.web_traffic_sniffer import (
    get_or_create_web_policy,
    get_web_activity_analytics,
    get_active_web_sessions,
    record_web_activity,
    start_web_traffic_sniffer,
    stop_web_traffic_sniffer,
)

router = APIRouter(prefix="/web-activity", tags=["Web Activity & Policy"])


class WebActivityLogResponse(BaseModel):
    id: int
    device_id: int | None
    ip_address: str
    mac_address: str | None
    hostname: str | None
    domain: str
    category: str
    protocol: str
    is_violation: bool
    action: str
    hit_count: int
    timestamp: datetime

    class Config:
        from_attributes = True


class WebFilterPolicyResponse(BaseModel):
    id: int
    block_streaming_work_hours: bool
    block_gaming_work_hours: bool
    block_social_media_work_hours: bool
    block_adult_always: bool
    enforce_schedule: bool
    custom_blocked_domains: str | None
    custom_allowed_domains: str | None
    sniffer_enabled: bool
    updated_at: datetime

    class Config:
        from_attributes = True


class UpdateWebFilterPolicyRequest(BaseModel):
    block_streaming_work_hours: bool | None = None
    block_gaming_work_hours: bool | None = None
    block_social_media_work_hours: bool | None = None
    block_adult_always: bool | None = None
    enforce_schedule: bool | None = None
    custom_blocked_domains: str | None = None
    custom_allowed_domains: str | None = None
    sniffer_enabled: bool | None = None


class ManualLogRequest(BaseModel):
    ip_address: str
    domain: str
    protocol: str = "PROBE"


@router.get("/active-sessions")
def get_active_sessions(
    minutes: int = Query(5, ge=1, le=60),
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_current_user),
):
    """Retrieve currently connected devices and domains active within the last N minutes."""
    return get_active_web_sessions(db, minutes=minutes)


@router.get("/logs", response_model=list[WebActivityLogResponse])
def get_web_activity_logs(
    category: str | None = None,
    violations_only: bool = False,
    ip_address: str | None = None,
    device_id: int | None = None,
    minutes: int | None = None,
    limit: int = Query(150, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_current_user),
):
    """List recent web activity logs with optional category, IP, minutes, and violation filters."""
    q = select(WebActivityLog).order_by(desc(WebActivityLog.timestamp))

    if minutes is not None and minutes > 0:
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=minutes)
        q = q.where(WebActivityLog.timestamp >= cutoff)
    if category:
        q = q.where(WebActivityLog.category == category)
    if violations_only:
        q = q.where(WebActivityLog.is_violation == True)
    if ip_address:
        q = q.where(WebActivityLog.ip_address == ip_address.strip())
    if device_id:
        q = q.where(WebActivityLog.device_id == device_id)

    q = q.offset(offset).limit(limit)
    return db.scalars(q).all()


@router.delete("/logs")
def clear_web_activity_logs(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Clear all historical web activity logs."""
    db.query(WebActivityLog).delete()
    db.commit()
    return {"message": "Web activity logs cleared successfully"}


@router.get("/analytics")
def get_web_analytics(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_current_user),
):
    """Retrieve web activity breakdown, top streaming/gaming users, and violation metrics."""
    return get_web_activity_analytics(db, hours=hours)


@router.get("/policy", response_model=WebFilterPolicyResponse)
def get_web_policy(
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_current_user),
):
    """Get the current institution web filtering and monitoring policy."""
    return get_or_create_web_policy(db)


@router.put("/policy", response_model=WebFilterPolicyResponse)
def update_web_policy(
    payload: UpdateWebFilterPolicyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Update institution web filtering and monitoring policy."""
    policy = get_or_create_web_policy(db)
    if payload.block_streaming_work_hours is not None:
        policy.block_streaming_work_hours = payload.block_streaming_work_hours
    if payload.block_gaming_work_hours is not None:
        policy.block_gaming_work_hours = payload.block_gaming_work_hours
    if payload.block_social_media_work_hours is not None:
        policy.block_social_media_work_hours = payload.block_social_media_work_hours
    if payload.block_adult_always is not None:
        policy.block_adult_always = payload.block_adult_always
    if payload.enforce_schedule is not None:
        policy.enforce_schedule = payload.enforce_schedule
    if payload.custom_blocked_domains is not None:
        policy.custom_blocked_domains = payload.custom_blocked_domains
    if payload.custom_allowed_domains is not None:
        policy.custom_allowed_domains = payload.custom_allowed_domains
    if payload.sniffer_enabled is not None:
        policy.sniffer_enabled = payload.sniffer_enabled
        if payload.sniffer_enabled:
            start_web_traffic_sniffer()
        else:
            stop_web_traffic_sniffer()

    policy.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(policy)
    return policy


@router.post("/log", response_model=WebActivityLogResponse)
def log_activity_entry(
    payload: ManualLogRequest,
    db: Session = Depends(get_db),
):
    """Endpoint for routers, NetOps probes, or agents to post observed DNS/web connections."""
    entry = record_web_activity(
        db=db,
        ip_address=payload.ip_address,
        domain=payload.domain,
        protocol=payload.protocol,
    )
    if not entry:
        raise HTTPException(status_code=400, detail="Invalid domain or IP address.")
    return entry
