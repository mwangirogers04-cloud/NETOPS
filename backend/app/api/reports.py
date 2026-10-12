from datetime import datetime, timedelta
from io import BytesIO
from xml.sax.saxutils import escape as xml_escape

from fastapi.responses import Response, StreamingResponse
from openpyxl import Workbook
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
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.device import Device
from ..models.event import Event


router = APIRouter(
    prefix="/reports",
    tags=["Reports"],
)


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
                "Use device_inventory, "
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
    worksheet = workbook.active
    worksheet.title = "NETOPS Report"

    # -------------------------------------------------
    # REPORT INFORMATION
    # -------------------------------------------------

    worksheet["A1"] = "NETOPS REPORT"
    worksheet["A2"] = "Report Type"
    worksheet["B2"] = report["report_type"]

    worksheet["A3"] = "Period"
    worksheet["B3"] = report["period"]

    worksheet["A4"] = "Start"
    worksheet["B4"] = report["start"]

    worksheet["A5"] = "End"
    worksheet["B5"] = report["end"]

    worksheet["A6"] = "Generated At"
    worksheet["B6"] = report["generated_at"]

    # -------------------------------------------------
    # DEVICE INVENTORY REPORT
    # -------------------------------------------------

    if report_type.lower().strip() == "device_inventory":

        summary = report["summary"]

        worksheet["A8"] = "SUMMARY"
        worksheet["A9"] = "Total Devices"
        worksheet["B9"] = summary["total_devices"]

        worksheet["A10"] = "Online Devices"
        worksheet["B10"] = summary["online_devices"]

        worksheet["A11"] = "Pending Approvals"
        worksheet["B11"] = summary["pending_approvals"]

        worksheet["A12"] = "Approved Devices"
        worksheet["B12"] = summary["approved_devices"]

        worksheet["A13"] = "Rejected Devices"
        worksheet["B13"] = summary["rejected_devices"]

        worksheet["A14"] = "Quarantined Devices"
        worksheet["B14"] = summary["quarantined_devices"]

        worksheet["A15"] = "Allowed Devices"
        worksheet["B15"] = summary["allowed_devices"]

        headers = [
            "ID",
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

        start_row = 18

        for column, header in enumerate(headers, start=1):
            worksheet.cell(
                row=start_row,
                column=column,
                value=header,
            )

        for row_index, device in enumerate(
            report["devices"],
            start=start_row + 1,
        ):
            values = [
                device["id"],
                device["ip_address"],
                device["mac_address"],
                device["hostname"],
                device["vendor"],
                device["device_type"],
                device["vlan_id"],
                device["status"],
                device["approval_status"],
                device["enforcement_status"],
                device["classification_status"],
                device["switch_name"],
                device["switch_port"],
            ]

            for column, value in enumerate(
                values,
                start=1,
            ):
                worksheet.cell(
                    row=row_index,
                    column=column,
                    value=value,
                )

    # -------------------------------------------------
    # EVENT REPORT
    # -------------------------------------------------

    else:

        summary = report["summary"]

        worksheet["A8"] = "SUMMARY"
        worksheet["A9"] = "Total Events"
        worksheet["B9"] = summary["total_events"]

        worksheet["A11"] = "EVENT TYPE"
        worksheet["B11"] = "COUNT"

        summary_row = 12

        for event_type, count in summary["event_types"].items():
            worksheet.cell(
                row=summary_row,
                column=1,
                value=event_type,
            )

            worksheet.cell(
                row=summary_row,
                column=2,
                value=count,
            )

            summary_row += 1

        event_start_row = summary_row + 2

        headers = [
            "ID",
            "Event Type",
            "Message",
            "Device ID",
            "Created At",
        ]

        for column, header in enumerate(headers, start=1):
            worksheet.cell(
                row=event_start_row,
                column=column,
                value=header,
            )

        for row_index, event in enumerate(
            report["events"],
            start=event_start_row + 1,
        ):
            values = [
                event["id"],
                event["event_type"],
                event["message"],
                event["device_id"],
                event["created_at"],
            ]

            for column, value in enumerate(
                values,
                start=1,
            ):
                worksheet.cell(
                    row=row_index,
                    column=column,
                    value=value,
                )

    # -------------------------------------------------
    # FORMAT COLUMNS
    # -------------------------------------------------

    for column in worksheet.columns:
        max_length = 0
        column_letter = column[0].column_letter

        for cell in column:
            if cell.value is not None:
                max_length = max(
                    max_length,
                    len(str(cell.value)),
                )

        worksheet.column_dimensions[
            column_letter
        ].width = min(max_length + 2, 50)

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
