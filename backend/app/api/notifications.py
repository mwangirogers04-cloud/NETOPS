"""
NETOPS Real-Time Webhook & Security Alerting API Router
=====================================================
Provides endpoints for managing real-time webhook integrations (Slack, Discord, Generic JSON),
configuring security alert triggers, and executing live test dispatches.
"""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..models.user import User
from ..services.auth_service import (
    get_notification_settings,
    require_admin,
    save_notification_settings,
    send_email_message,
    send_sms_message,
)
from ..services.webhook_service import (
    DEFAULT_TRIGGERS,
    TRIGGER_LOCKOUT,
    TRIGGER_QUARANTINE,
    TRIGGER_ROGUE,
    TRIGGER_SWITCH_UNREACHABLE,
    TRIGGER_UNAUTHORIZED_CLI,
    dispatch_security_alert,
    test_webhook_endpoint,
)

router = APIRouter(
    prefix="/notifications",
    tags=["Notifications & Webhooks"],
)


class AlertSettingsUpdateRequest(BaseModel):
    webhook_enabled: bool | None = None
    webhook_url: str | None = None
    webhook_platform: str | None = None  # slack, discord, generic
    alert_email: str | None = None
    alert_email_enabled: bool | None = None
    triggers: dict[str, bool] | None = None
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from_email: str | None = None
    sms_provider: str | None = None
    sms_api_key: str | None = None
    sms_username: str | None = None
    sms_sender_id: str | None = None
    sms_webhook_url: str | None = None


class AlertTestRequest(BaseModel):
    channel: str = "webhook"  # "webhook", "email", "sms"
    recipient: str | None = ""
    webhook_platform: str | None = "slack"


class ManualAlertDispatchRequest(BaseModel):
    event_type: str
    message: str
    title: str | None = None
    severity: str = "critical"
    details: dict[str, Any] | None = None


@router.get("/triggers")
def get_available_triggers(current_user: User = Depends(require_admin)):
    """Return available notification triggers with operational descriptions."""
    return [
        {
            "id": TRIGGER_QUARANTINE,
            "name": "Device Quarantined / Isolated",
            "emoji": "🚨",
            "severity": "critical",
            "description": "Fires immediately when an endpoint is quarantined to VLAN 90, isolated, or rejected.",
            "default": True,
        },
        {
            "id": TRIGGER_ROGUE,
            "name": "Rogue / Unknown LAN Device Detected",
            "emoji": "⚠️",
            "severity": "warning",
            "description": "Fires when ARP / DHCP / port scans discover an unregistered MAC or static IP conflict on the LAN.",
            "default": True,
        },
        {
            "id": TRIGGER_LOCKOUT,
            "name": "Brute-Force Account Lockout",
            "emoji": "🔒",
            "severity": "critical",
            "description": "Fires when 3 consecutive failed login attempts occur on any user or administrator account.",
            "default": True,
        },
        {
            "id": TRIGGER_SWITCH_UNREACHABLE,
            "name": "Network Switch Unreachable",
            "emoji": "🔌",
            "severity": "critical",
            "description": "Fires when a managed switch fails health telemetry checks, drops offline, or rejects SSH credentials.",
            "default": True,
        },
        {
            "id": TRIGGER_UNAUTHORIZED_CLI,
            "name": "Switch CLI Drift / Sensitive Discrepancy",
            "emoji": "📜",
            "severity": "critical",
            "description": "Fires when switch configuration backups detect modified secrets, unauthorized VLANs, trunk alterations, or BPDU guard removals.",
            "default": True,
        },
    ]


@router.get("/settings")
def get_notification_settings_endpoint(current_user: User = Depends(require_admin)):
    """Retrieve active webhook, email, and SMS alert configurations."""
    cfg = get_notification_settings()
    return {
        "webhook_enabled": bool(cfg.get("webhook_enabled", False)),
        "webhook_url": cfg.get("webhook_url", ""),
        "webhook_platform": cfg.get("webhook_platform", "slack"),
        "webhook_configured": bool(cfg.get("webhook_url")),
        "alert_email": cfg.get("alert_email", ""),
        "alert_email_enabled": bool(cfg.get("alert_email_enabled", False)),
        "triggers": cfg.get("triggers", DEFAULT_TRIGGERS),
        "last_webhook_status": cfg.get("last_webhook_status"),
        "last_webhook_sent_at": cfg.get("last_webhook_sent_at"),
        "last_webhook_error": cfg.get("last_webhook_error"),
        "smtp_host": cfg.get("smtp_host", ""),
        "smtp_port": cfg.get("smtp_port", 587),
        "smtp_user": cfg.get("smtp_user", ""),
        "smtp_password": "••••••••" if cfg.get("smtp_password") else "",
        "smtp_from_email": cfg.get("smtp_from_email", "noreply@netops.local"),
        "smtp_configured": bool(cfg.get("smtp_host")),
        "sms_provider": cfg.get("sms_provider", "africastalking"),
        "sms_api_key": "••••••••" if cfg.get("sms_api_key") else "",
        "sms_username": cfg.get("sms_username", ""),
        "sms_sender_id": cfg.get("sms_sender_id", ""),
        "sms_webhook_url": cfg.get("sms_webhook_url", ""),
        "sms_configured": bool(cfg.get("sms_api_key") or cfg.get("sms_webhook_url")),
    }


@router.post("/settings")
def update_notification_settings_endpoint(
    req: AlertSettingsUpdateRequest,
    current_user: User = Depends(require_admin),
):
    """Save webhook, email, and SMS alert configuration settings."""
    saved = save_notification_settings(req.model_dump())
    return {
        "status": "saved",
        "message": "Notification & Real-Time Alerting settings saved successfully.",
        "webhook_configured": bool(saved.get("webhook_url")),
        "webhook_enabled": bool(saved.get("webhook_enabled")),
        "smtp_configured": bool(saved.get("smtp_host")),
    }


@router.post("/test")
def test_notification_channel(
    req: AlertTestRequest,
    current_user: User = Depends(require_admin),
):
    """Send a live test alert to verify the webhook, email, or SMS destination."""
    ch = req.channel.strip().lower()
    recipient = (req.recipient or "").strip()
    cfg = get_notification_settings()

    if ch == "webhook":
        target_url = recipient or cfg.get("webhook_url") or ""
        if not target_url:
            raise HTTPException(
                status_code=400,
                detail="Please enter a target Webhook URL or configure one first in settings.",
            )
        platform = req.webhook_platform or cfg.get("webhook_platform", "slack")
        ok, detail = test_webhook_endpoint(webhook_url=target_url, webhook_platform=platform)
        return {
            "delivered": ok,
            "channel": "webhook",
            "platform": platform,
            "recipient": target_url,
            "detail": detail,
        }

    if not recipient:
        if ch == "email":
            recipient = cfg.get("alert_email") or cfg.get("smtp_user") or ""
        if not recipient:
            raise HTTPException(status_code=400, detail="Please enter a recipient email or phone number.")

    if ch == "email":
        ok, detail = send_email_message(
            to_email=recipient,
            subject="NETOPS Live Alert Test",
            html_body="<h3>✅ NETOPS Alert System Test</h3><p>Your emergency email alert channel is active and operating.</p>",
            plain_body="NETOPS Alert System Test: Your emergency email alert channel is active.",
        )
    elif ch == "sms":
        ok, detail = send_sms_message(
            phone_number=recipient,
            message_text="NETOPS Alert System Test: Emergency SMS alerts are verified and working.",
        )
    else:
        raise HTTPException(status_code=400, detail="Channel must be 'webhook', 'email', or 'sms'.")

    return {
        "delivered": ok,
        "channel": ch,
        "recipient": recipient,
        "detail": detail,
    }


@router.post("/dispatch")
def dispatch_alert_endpoint(
    req: ManualAlertDispatchRequest,
    current_user: User = Depends(require_admin),
):
    """Manually or programmatically dispatch an alert via configured channels."""
    res = dispatch_security_alert(
        event_type=req.event_type,
        message=req.message,
        title=req.title,
        details=req.details,
        severity=req.severity,
        sync=True,
    )
    return res
