from datetime import datetime, timedelta
from io import BytesIO
from xml.sax.saxutils import escape as xml_escape

from fastapi.responses import Response, StreamingResponse
from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.device import Device
from ..models.event import Event
from ..models.user import User, UserSession
from ..services.auth_service import decode_access_token, security_bearer


def verify_report_admin_access(
    token: str | None = None,
    credentials: HTTPAuthorizationCredentials | None = Depends(security_bearer),
    db: Session = Depends(get_db),
):
    """Enforce that standard users cannot generate or download reports."""
    raw_token = credentials.credentials if credentials else token
    if not raw_token:
        return None
    payload = decode_access_token(raw_token)
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token payload.")
    user = db.scalar(select(User).where(func.lower(User.username) == username.lower()))
    if not user or not user.is_active:
        raise HTTPException(status_code=403, detail="User account is inactive.")
    if user.role not in ("admin", "super_admin"):
        raise HTTPException(
            status_code=403,
            detail="Access denied: Standard users are not permitted to generate or download reports.",
        )
    return user


router = APIRouter(
    prefix="/reports",
    tags=["Reports"],
    dependencies=[Depends(verify_report_admin_access)],
)


def format_seconds(seconds: int | float | None) -> str:
    """Format duration in seconds into human-readable 'Xh Ym Zs'."""
    if not seconds or seconds <= 0:
        return "0s"
    sec = int(seconds)
    hours, remainder = divmod(sec, 3600)
    minutes, s = divmod(remainder, 60)
    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0 or hours > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{s}s")
    return " ".join(parts)


# -------------------------------------------------------------
# SMART EXCEL STYLING CONSTANTS & HELPERS
# -------------------------------------------------------------

EXCEL_HEADER_FONT = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
EXCEL_HEADER_FILL = PatternFill(start_color="1F4E79", end_color="1F4E79", fill_type="solid")
EXCEL_HEADER_ALIGN = Alignment(horizontal="center", vertical="center", wrap_text=True)

EXCEL_DATA_FONT = Font(name="Calibri", size=11, color="1E293B")
EXCEL_ALIGN_LEFT = Alignment(horizontal="left", vertical="center")
EXCEL_ALIGN_CENTER = Alignment(horizontal="center", vertical="center")

EXCEL_ZEBRA_FILL = PatternFill(start_color="F8FAFC", end_color="F8FAFC", fill_type="solid")

_BORDER_SIDE = Side(border_style="thin", color="E2E8F0")
EXCEL_CELL_BORDER = Border(
    left=_BORDER_SIDE,
    right=_BORDER_SIDE,
    top=_BORDER_SIDE,
    bottom=_BORDER_SIDE,
)


def populate_smart_excel_sheet(
    ws,
    headers: list[str],
    rows: list[list],
    center_columns: set[int] | None = None,
):
    """
    Populates an Excel worksheet ensuring the column headings appear at the top
    (Row 1), followed immediately by the content rows, with professional styling:
    - Bold white headings with dark corporate navy background
    - Locked/frozen header row so headers stay visible during scrolling
    - Native Excel auto-filter dropdowns on all columns
    - Alternating row zebra striping and thin grid borders
    - Auto-adjusted column widths with padding
    """
    if center_columns is None:
        center_columns = set()

    # 1. Row 1: Column Headings at the very top
    ws.row_dimensions[1].height = 28
    for col_idx, header in enumerate(headers, start=1):
        cell = ws.cell(row=1, column=col_idx, value=header)
        cell.font = EXCEL_HEADER_FONT
        cell.fill = EXCEL_HEADER_FILL
        cell.alignment = EXCEL_HEADER_ALIGN
        cell.border = EXCEL_CELL_BORDER

    # 2. Rows 2+: Content inside each column
    for row_idx, row_values in enumerate(rows, start=2):
        ws.row_dimensions[row_idx].height = 20
        is_even = (row_idx % 2 == 0)
        for col_idx, value in enumerate(row_values, start=1):
            cell = ws.cell(row=row_idx, column=col_idx, value=value)
            cell.font = EXCEL_DATA_FONT
            cell.border = EXCEL_CELL_BORDER
            if is_even:
                cell.fill = EXCEL_ZEBRA_FILL
            if col_idx in center_columns:
                cell.alignment = EXCEL_ALIGN_CENTER
            else:
                cell.alignment = EXCEL_ALIGN_LEFT

    # 3. Freeze panes at row 2 so column headings stay fixed at top
    ws.freeze_panes = "A2"

    # 4. Auto-filter on column headings
    max_col_letter = get_column_letter(len(headers))
    total_rows = max(len(rows) + 1, 1)
    ws.auto_filter.ref = f"A1:{max_col_letter}{total_rows}"

    # 5. Smart column width auto-calculation
    for col in ws.columns:
        col_letter = get_column_letter(col[0].column)
        max_len = 0
        for cell in col:
            val = cell.value
            if val is not None:
                max_len = max(max_len, len(str(val)))
        ws.column_dimensions[col_letter].width = max(max_len + 4, 12)


def parse_report_datetime(value: str) -> datetime:
    """Parse ISO formatted datetime string supporting minutes, seconds, or dates."""
    if not value or not isinstance(value, str):
        raise ValueError("Datetime string is required.")
    cleaned = value.strip()
    for fmt in (
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
    ):
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(cleaned)
    except Exception:
        raise ValueError(
            "start_datetime and end_datetime must use YYYY-MM-DDTHH:MM format."
        )


def parse_report_date(value: str) -> datetime:
    """Parse date string formatted as YYYY-MM-DD."""
    if not value or not isinstance(value, str):
        raise ValueError("Date string is required.")
    return datetime.strptime(value.strip(), "%Y-%m-%d")


def get_period_range(
    period: str,
    date: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    start_datetime: str | None = None,
    end_datetime: str | None = None,
):
    """
    Calculate the start and end datetime for a report period.

    Supported periods:
        hourly
        daily
        weekly
        monthly
        annually
        custom
    """

    period = period.lower().strip()

    if date:
        try:
            base_date = parse_report_date(date)
        except (ValueError, TypeError):
            raise HTTPException(
                status_code=400,
                detail="Date must use YYYY-MM-DD format",
            )
    else:
        now = datetime.utcnow()
        base_date = datetime(
            now.year,
            now.month,
            now.day,
        )

    if period == "hourly":
        start = base_date
        end = start + timedelta(hours=1)

    elif period == "daily":
        start = base_date
        end = start + timedelta(days=1)

    elif period == "weekly":
        start = base_date - timedelta(
            days=base_date.weekday()
        )
        end = start + timedelta(days=7)

    elif period == "monthly":
        start = datetime(
            base_date.year,
            base_date.month,
            1,
        )

        if base_date.month == 12:
            end = datetime(
                base_date.year + 1,
                1,
                1,
            )
        else:
            end = datetime(
                base_date.year,
                base_date.month + 1,
                1,
            )

    elif period == "annually":
        start = datetime(
            base_date.year,
            1,
            1,
        )
        end = datetime(
            base_date.year + 1,
            1,
            1,
        )

    elif period == "custom":
        if start_datetime and end_datetime:
            try:
                start = parse_report_datetime(start_datetime)
                end = parse_report_datetime(end_datetime)
            except (ValueError, TypeError):
                raise HTTPException(
                    status_code=400,
                    detail="start_datetime and end_datetime must use YYYY-MM-DDTHH:MM format.",
                )

            if end <= start:
                raise HTTPException(
                    status_code=400,
                    detail="end_datetime must be after start_datetime.",
                )

        elif start_date and end_date:
            try:
                start = parse_report_date(start_date)
                end = parse_report_date(end_date) + timedelta(days=1)
            except (ValueError, TypeError):
                raise HTTPException(
                    status_code=400,
                    detail="start_date and end_date must use YYYY-MM-DD format.",
                )

            if end <= start:
                raise HTTPException(
                    status_code=400,
                    detail="end_date must be on or after start_date.",
                )

        else:
            raise HTTPException(
                status_code=400,
                detail="Custom period requires start_datetime and end_datetime.",
            )
    else:
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid period. "
                "Use hourly, daily, weekly, "
                "monthly, annually, or custom."
            ),
        )

    return start, end


def get_custom_date_range(start_date: str, end_date: str):
    try:
        if not start_date or not end_date:
            raise ValueError("Dates are required.")
        start = parse_report_date(start_date)
        end = parse_report_date(end_date) + timedelta(days=1)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=400,
            detail="Dates must use YYYY-MM-DD format.",
        )

    if start >= end:
        raise HTTPException(
            status_code=400,
            detail="Start date must be before or equal to end date.",
        )

    return start, end



@router.get("/generate")
def generate_report(
    report_type: str,
    period: str,
    date: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    start_datetime: str | None = None,
    end_datetime: str | None = None,
    db: Session = Depends(get_db),
):
    """
    Generate a historical NETOPS report.

    Historical event-based reports use the events table.
    Device inventory reports use the current devices table.
    """
    start, end = get_period_range(
        period,
        date,
        start_date,
        end_date,
        start_datetime,
        end_datetime,
    )

    report_type = report_type.lower().strip()

    # -----------------------------------------------------
    # USER ACTIVITY & ACCESS REPORT
    # -----------------------------------------------------

    if report_type == "user_activity":
        # 1. Users created during the specified period
        users_created = db.scalars(
            select(User)
            .where(
                User.created_at >= start,
                User.created_at < end,
            )
            .order_by(User.created_at.desc())
        ).all()

        all_users = db.scalars(
            select(User).order_by(User.id.asc())
        ).all()

        # 2. Access sessions in or active during the period
        sessions = db.scalars(
            select(UserSession)
            .where(
                UserSession.login_at < end,
                or_(
                    UserSession.login_at >= start,
                    UserSession.last_activity_at >= start,
                    and_(UserSession.is_active.is_(True), UserSession.login_at <= end),
                ),
            )
            .order_by(UserSession.login_at.desc())
        ).all()

        total_duration_sec = sum(s.duration_seconds or 0 for s in sessions)
        avg_duration_sec = (
            int(round(total_duration_sec / len(sessions))) if sessions else 0
        )

        return {
            "report_type": "user_activity",
            "period": period,
            "start": start.isoformat(),
            "end": end.isoformat(),
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_users": len(all_users),
                "users_created_in_period": len(users_created),
                "total_sessions": len(sessions),
                "active_sessions": sum(1 for s in sessions if s.is_active),
                "total_duration_seconds": total_duration_sec,
                "total_duration_formatted": format_seconds(total_duration_sec),
                "average_duration_seconds": avg_duration_sec,
                "average_duration_formatted": format_seconds(avg_duration_sec),
            },
            "users_created": [
                {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "phone_number": user.phone_number,
                    "role": user.role,
                    "is_active": user.is_active,
                    "is_verified": user.is_verified,
                    "created_at": (
                        user.created_at.isoformat() if user.created_at else None
                    ),
                }
                for user in users_created
            ],
            "sessions": [
                {
                    "id": session.id,
                    "user_id": session.user_id,
                    "username": session.username,
                    "role": session.role,
                    "ip_address": session.ip_address,
                    "user_agent": session.user_agent,
                    "login_at": (
                        session.login_at.isoformat()
                        if session.login_at
                        else None
                    ),
                    "last_activity_at": (
                        session.last_activity_at.isoformat()
                        if session.last_activity_at
                        else None
                    ),
                    "logout_at": (
                        session.logout_at.isoformat()
                        if session.logout_at
                        else None
                    ),
                    "duration_seconds": session.duration_seconds or 0,
                    "duration_formatted": format_seconds(
                        session.duration_seconds or 0
                    ),
                    "is_active": session.is_active,
                }
                for session in sessions
            ],
        }

    # -----------------------------------------------------
    # DEVICE INVENTORY
    # -----------------------------------------------------

    if report_type == "device_inventory":
        devices = db.scalars(
            select(Device)
            .order_by(Device.id)
        ).all()

        return {
            "report_type": "device_inventory",
            "period": period,
            "start": start.isoformat(),
            "end": end.isoformat(),
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_devices": len(devices),
                "online_devices": sum(
                    1
                    for device in devices
                    if device.status == "online"
                ),
                "pending_approvals": sum(
                    1
                    for device in devices
                    if device.approval_status == "pending"
                ),
                "approved_devices": sum(
                    1
                    for device in devices
                    if device.approval_status == "approved"
                ),
                "rejected_devices": sum(
                    1
                    for device in devices
                    if device.approval_status == "rejected"
                ),
                "quarantined_devices": sum(
                    1
                    for device in devices
                    if device.enforcement_status
                    == "quarantined"
                ),
                "allowed_devices": sum(
                    1
                    for device in devices
                    if device.enforcement_status
                    == "allowed"
                ),
            },
            "devices": [
                {
                    "id": device.id,
                    "ip_address": device.ip_address,
                    "mac_address": device.mac_address,
                    "hostname": device.hostname,
                    "vendor": device.vendor,
                    "device_type": device.device_type,
                    "vlan_id": device.vlan_id,
                    "status": device.status,
                    "approval_status": device.approval_status,
                    "enforcement_status": (
                        device.enforcement_status
                    ),
                    "classification_status": (
                        device.classification_status
                    ),
                    "switch_name": device.switch_name,
                    "switch_port": device.switch_port,
                }
                for device in devices
            ],
        }

    # -----------------------------------------------------
    # HISTORICAL EVENT REPORTS
    # -----------------------------------------------------

    events = db.scalars(
        select(Event)
        .where(
            Event.created_at >= start,
            Event.created_at < end,
        )
        .order_by(Event.created_at.asc())
    ).all()

    # -----------------------------------------------------
    # EVENT TYPE COUNTS
    # -----------------------------------------------------

    event_type_counts = db.execute(
        select(
            Event.event_type,
            func.count(Event.id),
        )
        .where(
            Event.created_at >= start,
            Event.created_at < end,
        )
        .group_by(Event.event_type)
        .order_by(
            func.count(Event.id).desc()
        )
    ).all()

    

    # -----------------------------------------------------
    # FILTER EVENTS BY REPORT CATEGORY
    # -----------------------------------------------------

    if report_type == "network_events":
        filtered_events = events
    elif report_type == "device_discovery":
        filtered_events = [
            event
            for event in events
            if event.event_type.lower()
            == "device_detected"
        ]

    elif report_type == "access_enforcement":
        filtered_events = [
            event
            for event in events
            if event.event_type.lower()
            in {
                "access_enforcement",
                "internet_access_allowed",
                "internet_access_disallowed",
            }
        ]

    
    elif report_type == "approvals":
        filtered_events = [
            event
            for event in events
            if event.event_type.lower()
            in {
                "device_approved",
                "device_rejected",
            }
        ]

    elif report_type == "quarantine":
        filtered_events = [
            event
            for event in events
            if (
                event.event_type.lower()
                in {
                    "internet_access_disallowed",
                    "device_rejected",
                }
                or (
                    event.event_type.lower()
                    == "access_enforcement"
                    and "access blocked"
                    in (event.message or "").lower()
                )
            )
        ]

    elif report_type == "device_classification":

        keywords = (
            "classif",
        )

        filtered_events = [
            event
            for event in events
            if any(
                keyword in event.event_type.lower()
                or keyword in (event.message or "").lower()
                for keyword in keywords
            )
        ]

    elif report_type == "vlan_automation":
        filtered_events = [
            event
            for event in events
            if event.event_type.lower()
            == "vlan_automation"
        ]
    elif report_type == "network_activity":
        filtered_events = [
            event
            for event in events
            if event.event_type.lower()
            in {
                "access_enforcement",
                "internet_access_allowed",
                "internet_access_disallowed",
                "vlan_automation",
                "device_detected",
                "new_device",
            }
        ]

    elif report_type == "system_activity":
        filtered_events = events

    else:
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid report_type. "
                "Use device_inventory, user_activity, "
                "device_discovery, network_events, "
                "access_enforcement, approvals, "
                "quarantine, device_classification, "
                "vlan_automation, or system_activity."
            ),
        )

    filtered_event_type_counts = {}

    for event in filtered_events:
        filtered_event_type_counts[event.event_type] = (
            filtered_event_type_counts.get(event.event_type, 0) + 1
        )

    event_summary = filtered_event_type_counts

    return {
        "report_type": report_type,
        "period": period,
        "start": start.isoformat(),
        "end": end.isoformat(),
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "total_events": len(filtered_events),
            "event_types": event_summary,
        },
        "events": [
            {
                "id": event.id,
                "event_type": event.event_type,
                "message": event.message,
                "device_id": event.device_id,
                "created_at": (
                    event.created_at.isoformat()
                ),
            }
            for event in filtered_events
        ],
    }

# -----------------------------------------------------
# EXCEL REPORT EXPORT
# -----------------------------------------------------

@router.get("/export/excel")
def export_report_excel(
    report_type: str,
    period: str,
    date: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    start_datetime: str | None = None,
    end_datetime: str | None = None,
    db: Session = Depends(get_db),
):
    """
    Generate and download a NETOPS report as an Excel file.
    """

    report = generate_report(
    report_type=report_type,
    period=period,
    date=date,
    start_date=start_date,
    end_date=end_date,
    start_datetime=start_datetime,
    end_datetime=end_datetime,
    db=db,
)


    workbook = Workbook()
    clean_type = report_type.lower().strip()

    # -------------------------------------------------
    # USER ACTIVITY & ACCESS REPORT
    # -------------------------------------------------
    if clean_type == "user_activity":
        # Sheet 1: User Access & Session History (Active tab)
        ws_sessions = workbook.active
        ws_sessions.title = "User Sessions"

        session_headers = [
            "Session ID",
            "Username",
            "Role",
            "Login Time",
            "Last Activity",
            "Logout Time",
            "Duration",
            "Duration (Seconds)",
            "IP Address",
            "Session Status",
        ]

        session_rows = []
        for s in report.get("sessions", []):
            session_rows.append([
                s.get("id"),
                s.get("username"),
                (s.get("role") or "").upper(),
                s.get("login_at") or "",
                s.get("last_activity_at") or "",
                (
                    s.get("logout_at")
                    if s.get("logout_at")
                    else ("Active Now" if s.get("is_active") else "N/A")
                ),
                s.get("duration_formatted", "0s"),
                s.get("duration_seconds", 0),
                s.get("ip_address") or "N/A",
                "Active" if s.get("is_active") else "Ended",
            ])

        if not session_rows:
            session_rows.append([
                "-",
                "No access sessions recorded",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
            ])

        populate_smart_excel_sheet(
            ws_sessions,
            headers=session_headers,
            rows=session_rows,
            center_columns={1, 3, 8, 10},
        )

        # Sheet 2: Users Created in Period
        ws_users = workbook.create_sheet(title="Users Created")
        user_headers = [
            "User ID",
            "Username",
            "Email",
            "Phone Number",
            "Role",
            "Created At",
            "Verification Status",
            "Account Status",
        ]

        user_rows = []
        for u in report.get("users_created", []):
            user_rows.append([
                u.get("id"),
                u.get("username"),
                u.get("email"),
                u.get("phone_number") or "N/A",
                (u.get("role") or "").upper(),
                u.get("created_at") or "",
                "Verified" if u.get("is_verified") else "Pending",
                "Active" if u.get("is_active") else "Inactive",
            ])

        if not user_rows:
            user_rows.append([
                "-",
                "No users created in this period",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
            ])

        populate_smart_excel_sheet(
            ws_users,
            headers=user_headers,
            rows=user_rows,
            center_columns={1, 5, 7, 8},
        )

        # Sheet 3: Report Summary & Metrics
        ws_summary = workbook.create_sheet(title="Report Summary")
        summary = report.get("summary", {})
        summary_headers = ["Parameter / Metric", "Value"]
        summary_rows = [
            ["Report Type", "User Access & Audit Report"],
            ["Period", report.get("period", "").capitalize()],
            ["Period Start", report.get("start", "")],
            ["Period End", report.get("end", "")],
            ["Report Generated At", report.get("generated_at", "")],
            ["Total Registered Users", summary.get("total_users", 0)],
            ["Users Created in Period", summary.get("users_created_in_period", 0)],
            ["Total Access Logins", summary.get("total_sessions", 0)],
            ["Active Sessions Now", summary.get("active_sessions", 0)],
            ["Total Access Duration", summary.get("total_duration_formatted", "0s")],
            ["Average Session Duration", summary.get("average_duration_formatted", "0s")],
        ]

        populate_smart_excel_sheet(
            ws_summary,
            headers=summary_headers,
            rows=summary_rows,
        )

        workbook.active = ws_sessions

    # -------------------------------------------------
    # DEVICE INVENTORY REPORT
    # -------------------------------------------------
    elif clean_type == "device_inventory":
        ws_devices = workbook.active
        ws_devices.title = "Device Inventory"

        device_headers = [
            "Device ID",
            "IP Address",
            "MAC Address",
            "Hostname",
            "Vendor",
            "Device Type",
            "VLAN ID",
            "Status",
            "Approval Status",
            "Enforcement Status",
            "Classification Status",
            "Switch Name",
            "Switch Port",
        ]

        device_rows = []
        for d in report.get("devices", []):
            device_rows.append([
                d.get("id"),
                d.get("ip_address") or "",
                d.get("mac_address") or "",
                d.get("hostname") or "",
                d.get("vendor") or "",
                d.get("device_type") or "",
                d.get("vlan_id") or "",
                d.get("status") or "",
                d.get("approval_status") or "",
                d.get("enforcement_status") or "",
                d.get("classification_status") or "",
                d.get("switch_name") or "",
                d.get("switch_port") or "",
            ])

        populate_smart_excel_sheet(
            ws_devices,
            headers=device_headers,
            rows=device_rows,
            center_columns={1, 7, 8, 9, 10},
        )

        # Sheet 2: Summary
        ws_summary = workbook.create_sheet(title="Report Summary")
        summary = report.get("summary", {})
        summary_headers = ["Parameter / Metric", "Value"]
        summary_rows = [
            ["Report Type", "Device Inventory"],
            ["Period", report.get("period", "").capitalize()],
            ["Period Start", report.get("start", "")],
            ["Period End", report.get("end", "")],
            ["Report Generated At", report.get("generated_at", "")],
            ["Total Devices", summary.get("total_devices", 0)],
            ["Online Devices", summary.get("online_devices", 0)],
            ["Pending Approvals", summary.get("pending_approvals", 0)],
            ["Approved Devices", summary.get("approved_devices", 0)],
            ["Rejected Devices", summary.get("rejected_devices", 0)],
            ["Quarantined Devices", summary.get("quarantined_devices", 0)],
            ["Allowed Devices", summary.get("allowed_devices", 0)],
        ]

        populate_smart_excel_sheet(
            ws_summary,
            headers=summary_headers,
            rows=summary_rows,
        )

        workbook.active = ws_devices

    # -------------------------------------------------
    # HISTORICAL EVENT REPORTS
    # -------------------------------------------------
    else:
        sheet_title = clean_type.replace("_", " ").title()[:30]
        ws_events = workbook.active
        ws_events.title = sheet_title

        event_headers = [
            "Event ID",
            "Event Type",
            "Message",
            "Device ID",
            "Timestamp",
        ]

        event_rows = []
        for e in report.get("events", []):
            event_rows.append([
                e.get("id"),
                e.get("event_type"),
                e.get("message") or "",
                e.get("device_id") or "N/A",
                e.get("created_at"),
            ])

        if not event_rows:
            event_rows.append([
                "-",
                "No events recorded during this period",
                "-",
                "-",
                "-",
            ])

        populate_smart_excel_sheet(
            ws_events,
            headers=event_headers,
            rows=event_rows,
            center_columns={1, 2, 4},
        )

        # Sheet 2: Summary & Breakdown
        ws_summary = workbook.create_sheet(title="Report Summary")
        summary = report.get("summary", {})
        summary_headers = ["Parameter / Metric", "Value"]
        summary_rows = [
            ["Report Type", report.get("report_type", "").replace("_", " ").title()],
            ["Period", report.get("period", "").capitalize()],
            ["Period Start", report.get("start", "")],
            ["Period End", report.get("end", "")],
            ["Report Generated At", report.get("generated_at", "")],
            ["Total Events", summary.get("total_events", 0)],
        ]
        for event_type, count in summary.get("event_types", {}).items():
            summary_rows.append([f"Count: {event_type}", count])

        populate_smart_excel_sheet(
            ws_summary,
            headers=summary_headers,
            rows=summary_rows,
        )

        workbook.active = ws_events

    # -------------------------------------------------
    # CREATE FILE
    # -------------------------------------------------

    output = BytesIO()

    workbook.save(output)
    output.seek(0)

    filename = (
        f"netops_{report_type}_{period}.xlsx"
    )

    return Response(
    content=output.getvalue(),
    media_type=(
        "application/vnd.openxmlformats-officedocument."
        "spreadsheetml.sheet"
    ),
    headers={
        "Content-Disposition": (
            f'attachment; filename="{filename}"'
        )
    },
)
# -----------------------------------------------------
# PDF REPORT EXPORT
# -----------------------------------------------------

@router.get("/export/pdf")
def export_report_pdf(
    report_type: str,
    period: str,
    date: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
    start_datetime: str | None = None,
    end_datetime: str | None = None,
    db: Session = Depends(get_db),
):
    """
    Generate and download a NETOPS report as a PDF file.
    """

    report = generate_report(
    report_type=report_type,
    period=period,
    date=date,
    start_date=start_date,
    end_date=end_date,
    start_datetime=start_datetime,
    end_datetime=end_datetime,
    db=db,
)

    output = BytesIO()

    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=30,
        leftMargin=30,
        topMargin=30,
        bottomMargin=30,
    )

    styles = getSampleStyleSheet()

    story = []

    # -------------------------------------------------
    # TITLE
    # -------------------------------------------------

    story.append(
        Paragraph(
            "NETOPS REPORT",
            styles["Title"],
        )
    )

    story.append(
        Spacer(1, 12)
    )

    # -------------------------------------------------
    # REPORT INFORMATION
    # -------------------------------------------------

    report_information = [
        ["Report Type", report["report_type"]],
        ["Period", report["period"]],
        ["Start", report["start"]],
        ["End", report["end"]],
        ["Generated At", report["generated_at"]],
    ]

    information_table = Table(
        report_information,
        colWidths=[120, 350],
    )

    information_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.lightgrey,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.grey,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
            ]
        )
    )

    story.append(
        information_table
    )

    story.append(
        Spacer(1, 15)
    )

    # -------------------------------------------------
    # DEVICE INVENTORY PDF
    # -------------------------------------------------

    if report_type.lower().strip() == "device_inventory":

        summary = report["summary"]

        story.append(
            Paragraph(
                "Device Summary",
                styles["Heading2"],
            )
        )

        summary_data = [
            ["Metric", "Count"],
            [
                "Total Devices",
                str(summary["total_devices"]),
            ],
            [
                "Online Devices",
                str(summary["online_devices"]),
            ],
            [
                "Pending Approvals",
                str(summary["pending_approvals"]),
            ],
            [
                "Approved Devices",
                str(summary["approved_devices"]),
            ],
            [
                "Rejected Devices",
                str(summary["rejected_devices"]),
            ],
            [
                "Quarantined Devices",
                str(summary["quarantined_devices"]),
            ],
            [
                "Allowed Devices",
                str(summary["allowed_devices"]),
            ],
        ]

        summary_table = Table(
            summary_data,
            colWidths=[250, 100],
        )

        summary_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.lightgrey,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.grey,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                ]
            )
        )

        story.append(summary_table)

        story.append(
            Spacer(1, 15)
        )

        story.append(
            Paragraph(
                "Device Inventory",
                styles["Heading2"],
            )
        )

        device_data = [
            [
                "ID",
                "IP",
                "Hostname",
                "Type",
                "VLAN",
                "Status",
                "Approval",
            ]
        ]

        for device in report["devices"]:
            device_data.append(
                [
                    str(device["id"]),
                    str(device["ip_address"] or ""),
                    str(device["hostname"] or ""),
                    str(device["device_type"] or ""),
                    str(device["vlan_id"] or ""),
                    str(device["status"] or ""),
                    str(
                        device["approval_status"] or ""
                    ),
                ]
            )

        device_table = Table(
            device_data,
            repeatRows=1,
            colWidths=[
                30,
                70,
                80,
                60,
                40,
                60,
                70,
            ],
        )

        device_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.lightgrey,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.grey,
                    ),
                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                ]
            )
        )

        story.append(device_table)

    # -------------------------------------------------
    # USER ACTIVITY REPORT PDF
    # -------------------------------------------------

    elif report_type.lower().strip() == "user_activity":

        summary = report["summary"]

        story.append(
            Paragraph(
                "User Activity & Access Summary",
                styles["Heading2"],
            )
        )

        summary_data = [
            ["Metric", "Value"],
            ["Total Registered Users", str(summary["total_users"])],
            ["Users Created in Period", str(summary["users_created_in_period"])],
            ["Total Access Sessions", str(summary["total_sessions"])],
            ["Active Sessions", str(summary["active_sessions"])],
            ["Total Access Duration", str(summary["total_duration_formatted"])],
            ["Average Session Duration", str(summary["average_duration_formatted"])],
        ]

        summary_table = Table(
            summary_data,
            colWidths=[250, 150],
        )

        summary_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.lightgrey,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.grey,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                ]
            )
        )

        story.append(summary_table)

        story.append(
            Spacer(1, 15)
        )

        # -------------------------------------------------
        # SECTION 1: USERS CREATED IN PERIOD
        # -------------------------------------------------

        story.append(
            Paragraph(
                "Users Created in Period",
                styles["Heading2"],
            )
        )

        if report["users_created"]:
            user_table_data = [
                [
                    "ID",
                    "Username",
                    "Email",
                    "Role",
                    "Created At",
                    "Verified",
                    "Status",
                ]
            ]

            for user in report["users_created"]:
                user_table_data.append(
                    [
                        str(user["id"]),
                        str(user["username"] or ""),
                        str(user["email"] or ""),
                        str(user["role"] or ""),
                        str(user["created_at"] or "")[:19].replace("T", " "),
                        "Yes" if user["is_verified"] else "No",
                        "Active" if user["is_active"] else "Inactive",
                    ]
                )

            user_table = Table(
                user_table_data,
                repeatRows=1,
                colWidths=[
                    30,
                    80,
                    135,
                    60,
                    110,
                    60,
                    60,
                ],
            )

            user_table.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, 0),
                            colors.lightgrey,
                        ),
                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            0.5,
                            colors.grey,
                        ),
                        (
                            "FONTSIZE",
                            (0, 0),
                            (-1, -1),
                            7,
                        ),
                        (
                            "VALIGN",
                            (0, 0),
                            (-1, -1),
                            "TOP",
                        ),
                    ]
                )
            )

            story.append(user_table)
        else:
            story.append(
                Paragraph(
                    "No users were created during this period.",
                    styles["Italic"],
                )
            )

        story.append(
            Spacer(1, 15)
        )

        # -------------------------------------------------
        # SECTION 2: ACCESS & SESSION DURATION HISTORY
        # -------------------------------------------------

        story.append(
            Paragraph(
                "User Access & Session Duration History",
                styles["Heading2"],
            )
        )

        if report["sessions"]:
            session_table_data = [
                [
                    "User",
                    "Role",
                    "Login Time",
                    "Logout Time",
                    "Duration",
                    "IP Address",
                    "Status",
                ]
            ]

            for session in report["sessions"]:
                session_table_data.append(
                    [
                        str(session["username"] or ""),
                        str(session["role"] or ""),
                        str(session["login_at"] or "")[:19].replace("T", " "),
                        str(
                            session["logout_at"]
                            if session["logout_at"]
                            else ("Active" if session["is_active"] else "N/A")
                        )[:19].replace("T", " "),
                        str(session["duration_formatted"]),
                        str(session["ip_address"] or "N/A"),
                        "Active" if session["is_active"] else "Ended",
                    ]
                )

            session_table = Table(
                session_table_data,
                repeatRows=1,
                colWidths=[
                    75,
                    60,
                    105,
                    105,
                    65,
                    75,
                    50,
                ],
            )

            session_table.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, 0),
                            colors.lightgrey,
                        ),
                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            0.5,
                            colors.grey,
                        ),
                        (
                            "FONTSIZE",
                            (0, 0),
                            (-1, -1),
                            7,
                        ),
                        (
                            "VALIGN",
                            (0, 0),
                            (-1, -1),
                            "TOP",
                        ),
                    ]
                )
            )

            story.append(session_table)
        else:
            story.append(
                Paragraph(
                    "No access sessions recorded during this period.",
                    styles["Italic"],
                )
            )

    # -------------------------------------------------
    # EVENT REPORT PDF
    # -------------------------------------------------

    else:

        summary = report["summary"]

        story.append(
            Paragraph(
                "Event Summary",
                styles["Heading2"],
            )
        )

        story.append(
            Paragraph(
                f"Total Events: {summary['total_events']}",
                styles["BodyText"],
            )
        )

        story.append(
            Spacer(1, 10)
        )

        event_summary_data = [
            ["Event Type", "Count"]
        ]

        for event_type, count in summary[
            "event_types"
        ].items():
            event_summary_data.append(
                [
                    str(event_type),
                    str(count),
                ]
            )

        event_summary_table = Table(
            event_summary_data,
            colWidths=[300, 100],
        )

        event_summary_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.lightgrey,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.grey,
                    ),
                ]
            )
        )

        story.append(
            event_summary_table
        )

        story.append(
            Spacer(1, 15)
        )

        story.append(
            Paragraph(
                "Events",
                styles["Heading2"],
            )
        )

        event_data = [
            [
                "ID",
                "Type",
                "Message",
                "Device",
                "Created At",
            ]
        ]

        for event in report["events"]:

            message = str(
                event["message"] or ""
            )

            event_data.append(
                [
                    str(event["id"]),
                    str(
                        event["event_type"]
                        or ""
                    ),
                    Paragraph(
                        xml_escape(message),
                        styles["BodyText"],
                    ),
                    str(
                        event["device_id"]
                        or ""
                    ),
                    str(
                        event["created_at"]
                        or ""
                    ),
                ]
            )

        event_table = Table(
            event_data,
            repeatRows=1,
            colWidths=[
                30,
                80,
                220,
                50,
                100,
            ],
        )

        event_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.lightgrey,
                    ),
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.5,
                        colors.grey,
                    ),
                    (
                        "FONTSIZE",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                ]
            )
        )

        story.append(event_table)

    # -------------------------------------------------
    # BUILD PDF
    # -------------------------------------------------

    document.build(story)

    output.seek(0)

    filename = (
        f"netops_{report_type}_{period}.pdf"
    )

    return StreamingResponse(
        output,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            )
        },
    )
