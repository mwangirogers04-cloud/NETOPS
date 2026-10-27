"""
NETOPS Real-Time Webhook & Notification Alerting Service
======================================================
Dispatches immediate security and operational alerts via:
  - Slack Incoming Webhooks (Block Kit & Rich Attachments)
  - Discord Webhooks (Embedded Cards with Color Severity)
  - Generic / Custom HTTP Webhooks (JSON Payloads for SIEM / NOC)
  - Emergency Security Alert Email (via configured SMTP relay)

Supported Triggers:
  - device_quarantined: Device isolated or quarantined to VLAN 90
  - rogue_device_detected: Unrecognized or rogue endpoint discovered
  - auth_lockout: Account lockout triggered by 3 consecutive failed logins
  - switch_unreachable: Network switch hardware offline or unresponsive
  - unauthorized_cli_change: Configuration drift / sensitive discrepancy detected
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any

import httpx

from .auth_service import get_notification_settings, save_notification_settings, send_email_message

logger = logging.getLogger("netops.webhook")

# Standard Trigger Identifiers
TRIGGER_QUARANTINE = "device_quarantined"
TRIGGER_ROGUE = "rogue_device_detected"
TRIGGER_LOCKOUT = "auth_lockout"
TRIGGER_SWITCH_UNREACHABLE = "switch_unreachable"
TRIGGER_UNAUTHORIZED_CLI = "unauthorized_cli_change"

DEFAULT_TRIGGERS = {
    TRIGGER_QUARANTINE: True,
    TRIGGER_ROGUE: True,
    TRIGGER_LOCKOUT: True,
    TRIGGER_SWITCH_UNREACHABLE: True,
    TRIGGER_UNAUTHORIZED_CLI: True,
}


def map_event_type_to_trigger(event_type: str) -> str | None:
    """Map raw NETOPS event types to notification trigger categories."""
    et = (event_type or "").strip().lower()
    if et in (
        "device_quarantined",
        "device_isolated",
        "vlan_quarantine",
        "device_rejected",
        "quarantine_enforced",
    ):
        return TRIGGER_QUARANTINE
    if et in (
        "rogue_device_detected",
        "new_device",
        "device_detected",
        "unrecognized_endpoint",
        "ip_address_conflict",
    ):
        return TRIGGER_ROGUE
    if et in (
        "auth_lockout",
        "account_locked",
        "failed_login_lockout",
    ):
        return TRIGGER_LOCKOUT
    if et in (
        "switch_unreachable",
        "switch_offline",
        "switch_hardware_error",
        "switch_connection_failed",
    ):
        return TRIGGER_SWITCH_UNREACHABLE
    if et in (
        "unauthorized_cli_change",
        "switch_config_drift",
        "config_discrepancy",
    ):
        return TRIGGER_UNAUTHORIZED_CLI
    return None


def format_default_title(event_type: str, severity: str = "critical") -> str:
    """Return a human-friendly title with status emoji based on event type."""
    trigger = map_event_type_to_trigger(event_type)
    if trigger == TRIGGER_QUARANTINE:
        return "🚨 NETOPS Alert: Device Quarantined / Isolated"
    if trigger == TRIGGER_ROGUE:
        return "⚠️ NETOPS Alert: Rogue / Unregistered LAN Device Detected"
    if trigger == TRIGGER_LOCKOUT:
        return "🔒 NETOPS Security Alert: Brute-Force Account Lockout"
    if trigger == TRIGGER_SWITCH_UNREACHABLE:
        return "🔌 NETOPS Hardware Alert: Network Switch Unreachable"
    if trigger == TRIGGER_UNAUTHORIZED_CLI:
        return "📜 NETOPS Alert: Switch Configuration Drift / Sensitive Discrepancy"

    emoji = "🚨" if severity == "critical" else ("⚠️" if severity == "warning" else "ℹ️")
    return f"{emoji} NETOPS Security Alert: {event_type.replace('_', ' ').title()}"


def build_slack_payload(
    title: str,
    message: str,
    event_type: str,
    severity: str = "critical",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Format alert as a Slack incoming webhook payload with Block Kit & attachments."""
    color = (
        "#ef4444"
        if severity == "critical"
        else ("#f59e0b" if severity == "warning" else "#10b981")
    )
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    fields = [
        {"type": "mrkdwn", "text": f"*Event Type:*\n`{event_type}`"},
        {"type": "mrkdwn", "text": f"*Severity:*\n*{severity.upper()}*"},
        {"type": "mrkdwn", "text": f"*Timestamp:*\n{now_str}"},
    ]

    if details:
        for k, v in list(details.items())[:5]:
            label = k.replace("_", " ").title()
            val_str = str(v)
            if len(val_str) > 120:
                val_str = val_str[:117] + "..."
            fields.append({"type": "mrkdwn", "text": f"*{label}:*\n{val_str}"})

    return {
        "text": f"{title}: {message}",
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": title[:150],
                            "emoji": True,
                        },
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*Summary:*\n{message}"},
                    },
                    {
                        "type": "section",
                        "fields": fields,
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": "🛡️ *NETOPS Zero-Trust Network Access Control Platform*",
                            }
                        ],
                    },
                ],
            }
        ],
    }


def build_discord_payload(
    title: str,
    message: str,
    event_type: str,
    severity: str = "critical",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Format alert as a Discord webhook payload with rich embeds."""
    color_int = (
        0xEF4444
        if severity == "critical"
        else (0xF59E0B if severity == "warning" else 0x10B981)
    )
    now_iso = datetime.now(timezone.utc).isoformat()

    discord_fields = [
        {"name": "Trigger Event", "value": f"`{event_type}`", "inline": True},
        {"name": "Severity", "value": severity.upper(), "inline": True},
    ]

    if details:
        for k, v in list(details.items())[:6]:
            label = k.replace("_", " ").title()
            val_str = str(v)
            if len(val_str) > 200:
                val_str = val_str[:197] + "..."
            discord_fields.append({"name": label, "value": val_str, "inline": True})

    return {
        "content": f"🚨 **NETOPS Security Alert** | `{severity.upper()}`",
        "embeds": [
            {
                "title": title[:256],
                "description": message,
                "color": color_int,
                "fields": discord_fields,
                "footer": {"text": "NETOPS Zero-Trust Network Gateway"},
                "timestamp": now_iso,
            }
        ],
    }


def build_generic_payload(
    title: str,
    message: str,
    event_type: str,
    severity: str = "critical",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Format alert as a clean generic JSON payload for SIEM, NOC, or Zapier/n8n."""
    return {
        "platform": "netops",
        "source": "netops_alerting_engine",
        "title": title,
        "message": message,
        "event_type": event_type,
        "severity": severity,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": details or {},
    }


def send_webhook_request(
    url: str,
    payload: dict[str, Any],
    timeout_seconds: float = 6.0,
) -> tuple[bool, str]:
    """Deliver a JSON payload to a remote webhook URL."""
    cleaned_url = (url or "").strip()
    if not cleaned_url or not (cleaned_url.startswith("http://") or cleaned_url.startswith("https://")):
        return False, "Invalid webhook URL: must start with http:// or https://"

    try:
        with httpx.Client(timeout=timeout_seconds, follow_redirects=True) as client:
            resp = client.post(
                cleaned_url,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "NETOPS-Notification-Dispatcher/1.0",
                },
            )
            # Discord uses 204 No Content, Slack uses 200 OK
            if 200 <= resp.status_code < 300:
                return True, f"HTTP {resp.status_code} OK"
            return False, f"Remote returned HTTP {resp.status_code}: {resp.text[:200]}"
    except httpx.TimeoutException:
        return False, f"Webhook request timed out after {timeout_seconds}s"
    except httpx.ConnectError as err:
        return False, f"Connection failed: {err}"
    except Exception as exc:
        return False, f"Webhook dispatch error: {exc}"


def verify_webhook_endpoint(
    webhook_url: str,
    webhook_platform: str = "slack",
) -> tuple[bool, str]:
    """Send a live test notification payload to verify webhook configuration."""
    platform = (webhook_platform or "slack").strip().lower()
    title = "🧪 NETOPS Live Webhook Test"
    message = (
        "Your NETOPS Webhook Alert Channel is verified and active! Real-time alerts for "
        "quarantined devices, rogue LAN machines, brute-force lockouts, and switch configuration drift "
        "will be delivered to this channel."
    )
    details = {
        "status": "connected",
        "test_initiated_by": "administrator",
        "environment": "production_gateway",
    }

    if platform == "slack":
        payload = build_slack_payload(title, message, "test_ping", "info", details)
    elif platform == "discord":
        payload = build_discord_payload(title, message, "test_ping", "info", details)
    else:
        payload = build_generic_payload(title, message, "test_ping", "info", details)

    return send_webhook_request(webhook_url, payload)


# Backward-compatible alias
test_webhook_endpoint = verify_webhook_endpoint


def _execute_alert_dispatch(
    cfg: dict[str, Any],
    event_type: str,
    title: str,
    message: str,
    details: dict[str, Any] | None,
    severity: str,
) -> dict[str, Any]:
    """Synchronous execution worker that sends webhook and/or email."""
    webhook_url = (cfg.get("webhook_url") or "").strip()
    webhook_enabled = bool(cfg.get("webhook_enabled"))
    webhook_platform = (cfg.get("webhook_platform") or "slack").strip().lower()

    webhook_ok = False
    webhook_detail = "Webhook disabled or URL not configured"

    if webhook_enabled and webhook_url:
        if webhook_platform == "slack":
            payload = build_slack_payload(title, message, event_type, severity, details)
        elif webhook_platform == "discord":
            payload = build_discord_payload(title, message, event_type, severity, details)
        else:
            payload = build_generic_payload(title, message, event_type, severity, details)

        webhook_ok, webhook_detail = send_webhook_request(webhook_url, payload)

        # Update last dispatch status in configuration
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            save_notification_settings({
                "last_webhook_status": "success" if webhook_ok else "failed",
                "last_webhook_sent_at": now_iso,
                "last_webhook_error": None if webhook_ok else webhook_detail,
            })
        except Exception as exc:
            logger.warning(f"Failed to record last webhook status: {exc}")

    # Email Alert Dispatch (if configured & enabled)
    email_ok = False
    email_detail = "Alert email disabled or recipient not configured"
    alert_email = (cfg.get("alert_email") or "").strip()
    alert_email_enabled = bool(cfg.get("alert_email_enabled"))

    if alert_email_enabled and alert_email:
        subject = f"[NETOPS ALERT] {title}"
        html_body = f"""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; background: #0f172a; color: #f8fafc; border-radius: 8px; overflow: hidden; border: 1px solid #334155;">
          <div style="background: {'#dc2626' if severity == 'critical' else '#f59e0b'}; padding: 16px 20px;">
            <h2 style="margin: 0; color: #ffffff; font-size: 18px;">{title}</h2>
          </div>
          <div style="padding: 20px;">
            <p style="font-size: 14px; line-height: 1.6; color: #e2e8f0;">{message}</p>
            <div style="background: #1e293b; padding: 12px 16px; border-radius: 6px; margin-top: 16px; border: 1px solid #334155;">
              <table style="width: 100%; font-size: 13px; color: #94a3b8;">
                <tr><td style="padding: 4px 0; font-weight: 600;">Event Type:</td><td style="color: #38bdf8;">{event_type}</td></tr>
                <tr><td style="padding: 4px 0; font-weight: 600;">Severity:</td><td style="color: {'#f87171' if severity == 'critical' else '#fbbf24'}; text-transform: uppercase;">{severity}</td></tr>
                <tr><td style="padding: 4px 0; font-weight: 600;">Timestamp:</td><td style="color: #f8fafc;">{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
              </table>
            </div>
            <p style="font-size: 11px; color: #64748b; margin-top: 20px; border-top: 1px solid #334155; padding-top: 12px;">
              Automated message sent by NETOPS Zero-Trust Network Access Control Platform.
            </p>
          </div>
        </div>
        """
        email_ok, email_detail = send_email_message(
            to_email=alert_email,
            subject=subject,
            html_body=html_body,
            plain_body=f"{title}\n\n{message}\n\nEvent Type: {event_type}\nSeverity: {severity}",
        )

    return {
        "dispatched": webhook_ok or email_ok,
        "webhook_delivered": webhook_ok,
        "webhook_detail": webhook_detail,
        "email_delivered": email_ok,
        "email_detail": email_detail,
    }


def dispatch_security_alert(
    event_type: str,
    message: str,
    title: str | None = None,
    details: dict[str, Any] | None = None,
    severity: str = "critical",
    sync: bool = False,
) -> dict[str, Any]:
    """
    Dispatch a real-time security alert to configured webhooks and emergency email.

    Checks configured trigger preferences. If disabled for this trigger type,
    skips dispatch. If sync=False (default), offloads work to a background daemon thread
    to guarantee non-blocking execution inside database transactions.
    """
    cfg = get_notification_settings()

    # Check trigger rules
    trigger_key = map_event_type_to_trigger(event_type)
    triggers = cfg.get("triggers", {})
    if trigger_key and isinstance(triggers, dict):
        if triggers.get(trigger_key) is False:
            return {
                "dispatched": False,
                "reason": f"Trigger '{trigger_key}' is disabled in notification settings.",
            }

    final_title = title or format_default_title(event_type, severity)

    if sync:
        return _execute_alert_dispatch(cfg, event_type, final_title, message, details, severity)

    # Launch asynchronously in a daemon thread so the caller transaction does not block
    thread = threading.Thread(
        target=_execute_alert_dispatch,
        args=(cfg, event_type, final_title, message, details, severity),
        daemon=True,
    )
    thread.start()

    return {
        "status": "queued",
        "dispatched": True,
        "event_type": event_type,
        "trigger": trigger_key,
    }
