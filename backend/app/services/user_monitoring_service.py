from datetime import datetime, timezone, timedelta
import re
from fastapi import Request
from sqlalchemy import func, select, desc, distinct
from sqlalchemy.orm import Session

from ..models.user import User, UserSession


def get_real_client_ip(request: Request) -> str:
    """
    Extract the real client IP address, supporting Cloudflare, reverse proxies,
    and cloud application platforms.
    """
    # 1. Cloudflare connecting IP
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip and cf_ip.strip():
        return cf_ip.strip()

    # 2. Standard X-Real-IP
    real_ip = request.headers.get("x-real-ip")
    if real_ip and real_ip.strip():
        return real_ip.strip()

    # 3. Standard X-Forwarded-For (client is the first IP in the chain)
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and forwarded.strip():
        client_part = forwarded.split(",")[0].strip()
        if client_part:
            return client_part

    # 4. Fallback to direct socket connection
    if request.client and request.client.host:
        return request.client.host

    return "127.0.0.1"


def parse_user_agent(ua_str: str | None) -> dict:
    """
    Parse a User-Agent string into readable browser, OS, and device categories.
    """
    if not ua_str:
        return {
            "browser": "Unknown Browser",
            "os": "Unknown OS",
            "device": "Desktop",
            "summary": "Unknown Client",
        }

    ua = ua_str.strip()

    # Detect OS
    os_name = "Unknown OS"
    if "Windows NT 10.0" in ua:
        os_name = "Windows 10/11"
    elif "Windows NT 6.3" in ua:
        os_name = "Windows 8.1"
    elif "Windows NT 6.1" in ua:
        os_name = "Windows 7"
    elif "Windows" in ua:
        os_name = "Windows"
    elif "iPhone" in ua:
        os_name = "iOS (iPhone)"
    elif "iPad" in ua:
        os_name = "iPadOS"
    elif "Macintosh" in ua or "Mac OS X" in ua:
        os_name = "macOS"
    elif "Android" in ua:
        os_name = "Android"
    elif "Linux" in ua:
        os_name = "Linux"
    elif "CrOS" in ua:
        os_name = "ChromeOS"

    # Detect Device Type
    device_type = "Desktop"
    if "Mobile" in ua or "iPhone" in ua or "Android" in ua:
        device_type = "Mobile"
    if "iPad" in ua or "Tablet" in ua:
        device_type = "Tablet"

    # Detect Browser
    browser_name = "Unknown Browser"
    if "Edg/" in ua or "Edge/" in ua:
        m = re.search(r"Edg[e]?/(\d+)", ua)
        browser_name = f"Edge {m.group(1)}" if m else "Edge"
    elif "OPR/" in ua or "Opera" in ua:
        m = re.search(r"OPR/(\d+)", ua)
        browser_name = f"Opera {m.group(1)}" if m else "Opera"
    elif "Chrome/" in ua and "Chromium" not in ua:
        m = re.search(r"Chrome/(\d+)", ua)
        browser_name = f"Chrome {m.group(1)}" if m else "Chrome"
    elif "Firefox/" in ua:
        m = re.search(r"Firefox/(\d+)", ua)
        browser_name = f"Firefox {m.group(1)}" if m else "Firefox"
    elif "Safari/" in ua and "Chrome" not in ua:
        m = re.search(r"Version/(\d+)", ua)
        browser_name = f"Safari {m.group(1)}" if m else "Safari"

    summary = f"{browser_name} on {os_name}"
    return {
        "browser": browser_name,
        "os": os_name,
        "device": device_type,
        "summary": summary,
    }


def get_user_monitoring_summary(db: Session) -> dict:
    """
    Returns aggregated metrics for platform usage:
    - total_registered_users
    - online_users_count (active within past 3 minutes)
    - total_sessions_all_time
    - sessions_today_count
    - unique_users_today
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    active_threshold = now - timedelta(minutes=3)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    total_registered = db.scalar(select(func.count(User.id))) or 0

    # Online users: active session updated within 3 mins
    online_count = (
        db.scalar(
            select(func.count(distinct(UserSession.user_id))).where(
                UserSession.is_active.is_(True),
                UserSession.last_activity_at >= active_threshold,
            )
        )
        or 0
    )

    total_sessions = db.scalar(select(func.count(UserSession.id))) or 0

    sessions_today = (
        db.scalar(
            select(func.count(UserSession.id)).where(
                UserSession.login_at >= today_start
            )
        )
        or 0
    )

    unique_users_today = (
        db.scalar(
            select(func.count(distinct(UserSession.user_id))).where(
                UserSession.login_at >= today_start
            )
        )
        or 0
    )

    return {
        "total_registered_users": total_registered,
        "online_users_count": online_count,
        "total_sessions_all_time": total_sessions,
        "sessions_today_count": sessions_today,
        "unique_users_today": unique_users_today,
        "server_time": now.isoformat(),
    }


def get_live_active_sessions(db: Session) -> list[dict]:
    """
    Retrieve all sessions that are currently flagged as active and had activity in the last 10 minutes.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    threshold = now - timedelta(minutes=10)

    sessions = (
        db.execute(
            select(UserSession, User.email)
            .join(User, UserSession.user_id == User.id, isouter=True)
            .where(
                UserSession.is_active.is_(True),
                UserSession.last_activity_at >= threshold,
            )
            .order_by(desc(UserSession.last_activity_at))
        )
        .all()
    )

    results = []
    for s, email in sessions:
        device_meta = parse_user_agent(s.user_agent)
        idle_seconds = max(0, int((now - s.last_activity_at).total_seconds())) if s.last_activity_at else 0
        total_duration = max(0, int((now - s.login_at).total_seconds())) if s.login_at else s.duration_seconds
        is_strictly_online = idle_seconds <= 180  # 3 minutes

        results.append({
            "session_id": s.id,
            "user_id": s.user_id,
            "username": s.username,
            "email": email or "",
            "role": s.role,
            "ip_address": s.ip_address or "Unknown IP",
            "current_page": s.current_page or "dashboard",
            "user_agent": s.user_agent,
            "device": device_meta,
            "login_at": s.login_at.isoformat() if s.login_at else None,
            "last_activity_at": s.last_activity_at.isoformat() if s.last_activity_at else None,
            "duration_seconds": total_duration,
            "idle_seconds": idle_seconds,
            "is_online": is_strictly_online,
        })

    return results


def get_users_lifecycle_overview(db: Session) -> list[dict]:
    """
    Returns full directory of all registered users with:
    - first_seen (earliest recorded session or user creation date)
    - last_seen (latest session activity or login)
    - is_online (true if active session in last 3 min)
    - total_sessions
    - total_duration_seconds
    - last known IP and device
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    active_threshold = now - timedelta(minutes=3)

    users = db.scalars(select(User).order_by(User.id)).all()
    all_sessions = db.scalars(select(UserSession).order_by(UserSession.login_at.desc())).all()

    # Group sessions by user_id
    sessions_by_user: dict[int, list[UserSession]] = {}
    for s in all_sessions:
        sessions_by_user.setdefault(s.user_id, []).append(s)

    results = []
    for u in users:
        u_sessions = sessions_by_user.get(u.id, [])
        total_sessions = len(u_sessions)
        total_duration = sum(s.duration_seconds for s in u_sessions)

        # First seen is earliest login or user created_at
        first_seen_dt = u.created_at
        if u_sessions:
            earliest_session_dt = u_sessions[-1].login_at
            if earliest_session_dt and (not first_seen_dt or earliest_session_dt < first_seen_dt):
                first_seen_dt = earliest_session_dt

        # Last seen is latest session last_activity_at or login_at
        last_seen_dt = u.created_at
        last_ip = None
        last_ua = None
        current_page = None
        is_online = False

        if u_sessions:
            latest_session = u_sessions[0]
            last_seen_dt = latest_session.last_activity_at or latest_session.login_at
            last_ip = latest_session.ip_address
            last_ua = latest_session.user_agent
            
            # Check if any session is actively online right now
            for s in u_sessions:
                if s.is_active and s.last_activity_at and s.last_activity_at >= active_threshold:
                    is_online = True
                    current_page = s.current_page or "dashboard"
                    last_ip = s.ip_address
                    last_ua = s.user_agent
                    break

        device_meta = parse_user_agent(last_ua)

        results.append({
            "user_id": u.id,
            "username": u.username,
            "email": u.email,
            "role": u.role,
            "is_active": u.is_active,
            "is_verified": u.is_verified,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "first_seen": first_seen_dt.isoformat() if first_seen_dt else None,
            "last_seen": last_seen_dt.isoformat() if last_seen_dt else None,
            "is_online": is_online,
            "current_page": current_page,
            "last_ip": last_ip or "Never logged in",
            "last_device": device_meta,
            "total_sessions": total_sessions,
            "total_duration_seconds": total_duration,
        })

    # Sort so online users appear first, then by last_seen desc
    results.sort(key=lambda x: (not x["is_online"], x["last_seen"] or ""), reverse=False)
    return results


def get_sessions_history(
    db: Session,
    limit: int = 50,
    offset: int = 0,
    search: str | None = None,
    status_filter: str = "all",
) -> dict:
    """
    Paginated, searchable session history log with login_at, logout_at, duration, IP, device, and last page.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    active_threshold = now - timedelta(minutes=3)

    query = (
        select(UserSession, User.email)
        .join(User, UserSession.user_id == User.id, isouter=True)
    )

    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.where(
            (UserSession.username.ilike(term))
            | (UserSession.ip_address.ilike(term))
            | (User.email.ilike(term))
        )

    if status_filter == "online":
        query = query.where(
            UserSession.is_active.is_(True),
            UserSession.last_activity_at >= active_threshold,
        )
    elif status_filter == "active":
        query = query.where(UserSession.is_active.is_(True))
    elif status_filter == "ended":
        query = query.where(UserSession.is_active.is_(False))

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total_count = db.scalar(count_query) or 0

    # Fetch page
    query = query.order_by(desc(UserSession.login_at)).offset(offset).limit(limit)
    rows = db.execute(query).all()

    items = []
    for s, email in rows:
        device_meta = parse_user_agent(s.user_agent)
        is_strictly_online = (
            s.is_active
            and s.last_activity_at is not None
            and s.last_activity_at >= active_threshold
        )
        
        # Calculate dynamic duration if session is still active
        duration = s.duration_seconds
        if s.is_active and s.login_at:
            duration = max(1, int((now - s.login_at).total_seconds()))

        items.append({
            "session_id": s.id,
            "user_id": s.user_id,
            "username": s.username,
            "email": email or "",
            "role": s.role,
            "ip_address": s.ip_address or "Unknown IP",
            "current_page": s.current_page or "dashboard",
            "user_agent": s.user_agent,
            "device": device_meta,
            "login_at": s.login_at.isoformat() if s.login_at else None,
            "logout_at": s.logout_at.isoformat() if s.logout_at else None,
            "last_activity_at": s.last_activity_at.isoformat() if s.last_activity_at else None,
            "duration_seconds": duration,
            "is_active": s.is_active,
            "is_online": is_strictly_online,
        })

    return {
        "total": total_count,
        "offset": offset,
        "limit": limit,
        "items": items,
    }


def terminate_session(db: Session, session_id: int) -> bool:
    """
    Force terminate a specific session.
    """
    session = db.scalar(select(UserSession).where(UserSession.id == session_id))
    if not session or not session.is_active:
        return False

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    session.is_active = False
    session.logout_at = now
    session.last_activity_at = now
    if session.login_at:
        session.duration_seconds = max(1, int((now - session.login_at).total_seconds()))
    db.commit()
    return True


def terminate_all_user_sessions(db: Session, user_id: int) -> int:
    """
    Force terminate all active sessions for a given user.
    """
    active_sessions = db.scalars(
        select(UserSession).where(
            UserSession.user_id == user_id,
            UserSession.is_active.is_(True),
        )
    ).all()

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for s in active_sessions:
        s.is_active = False
        s.logout_at = now
        s.last_activity_at = now
        if s.login_at:
            s.duration_seconds = max(1, int((now - s.login_at).total_seconds()))

    db.commit()
    return len(active_sessions)
