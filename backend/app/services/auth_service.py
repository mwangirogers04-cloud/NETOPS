import json
import logging
from pathlib import Path
import secrets
import smtplib
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models.user import PasswordResetOTP, User, UserSession

logger = logging.getLogger("netops.auth")
security_bearer = HTTPBearer(auto_error=False)


# -------------------------------------------------------------
# EMAIL & PHONE DUPLICATE RECHECK HELPERS
# -------------------------------------------------------------

def normalize_phone_number(phone: str | None) -> str:
    """
    Normalize a phone number for duplicate comparison.
    Strips whitespace/separators and normalizes local 07XX/01XX or 2547XX/2541XX to +254...
    """
    if not phone:
        return ""
    cleaned = "".join(ch for ch in phone.strip() if ch.isdigit() or ch == "+")
    if not cleaned:
        return ""
    digits_only = "".join(ch for ch in cleaned if ch.isdigit())
    if len(digits_only) == 10 and (digits_only.startswith("07") or digits_only.startswith("01")):
        return "+254" + digits_only[1:]
    if len(digits_only) == 12 and (digits_only.startswith("2547") or digits_only.startswith("2541")):
        return "+" + digits_only
    if cleaned.startswith("+"):
        return "+" + digits_only
    return digits_only


def check_user_conflicts(
    db: Session,
    username: str | None = None,
    email: str | None = None,
    phone_number: str | None = None,
    exclude_user_id: int | None = None,
) -> dict:
    """
    Recheck whether a username, email address, or phone number is already registered
    to another account in the database.
    """
    clean_username = username.strip().lower() if username and username.strip() else None
    clean_email = str(email).strip().lower() if email and str(email).strip() else None
    norm_phone = normalize_phone_number(phone_number) if phone_number and phone_number.strip() else None
    raw_phone = phone_number.strip() if phone_number and phone_number.strip() else None

    users = db.scalars(select(User)).all()

    username_exists = False
    email_exists = False
    phone_exists = False

    for u in users:
        if exclude_user_id is not None and u.id == exclude_user_id:
            continue
        if clean_username and u.username and u.username.strip().lower() == clean_username:
            username_exists = True
        if clean_email and u.email and u.email.strip().lower() == clean_email:
            email_exists = True
        if norm_phone and u.phone_number:
            u_norm = normalize_phone_number(u.phone_number)
            if (u_norm and u_norm == norm_phone) or (raw_phone and u.phone_number.strip() == raw_phone):
                phone_exists = True

    email_message = (
        "The email address already exists, please try another email address."
        if email_exists
        else None
    )
    phone_message = (
        "The phone number already exists, please try another number."
        if phone_exists
        else None
    )
    username_message = (
        f"Username '{username.strip()}' is already taken, please try another username."
        if username_exists and username
        else None
    )

    if email_exists and phone_exists:
        detail = (
            "The email address and phone number already exist. "
            "Please try another email address and another number."
        )
    elif email_exists:
        detail = email_message
    elif phone_exists:
        detail = phone_message
    elif username_exists:
        detail = username_message
    else:
        detail = None

    return {
        "available": not (username_exists or email_exists or phone_exists),
        "username_exists": username_exists,
        "email_exists": email_exists,
        "phone_exists": phone_exists,
        "username_message": username_message,
        "email_message": email_message,
        "phone_message": phone_message,
        "detail": detail,
        "message": detail,
        "conflicts": {
            "username": username_message,
            "email": email_message,
            "phone_number": phone_message,
        },
    }


# -------------------------------------------------------------
# PASSWORD COMPLEXITY & HASHING
# -------------------------------------------------------------

def validate_password_complexity(password: str) -> str:
    """
    Validate that a password meets complexity requirements:
      - Minimum 8 characters
      - At least one uppercase letter (A-Z)
      - At least one lowercase letter (a-z)
      - At least one special character (non-alphanumeric)
    """
    if not password or len(password) < 8:
        raise ValueError(
            "Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, and one special character."
        )
    if not any(ch.isupper() for ch in password):
        raise ValueError(
            "Password must contain at least one uppercase letter (A-Z)."
        )
    if not any(ch.islower() for ch in password):
        raise ValueError(
            "Password must contain at least one lowercase letter (a-z)."
        )
    if not any(not ch.isalnum() and not ch.isspace() for ch in password):
        raise ValueError(
            "Password must contain at least one special character (e.g. @, #, $, %, !, &, *)."
        )
    return password


def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plain password against bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8"),
        )
    except Exception as exc:
        logger.warning(f"Password verification error: {exc}")
        return False


# -------------------------------------------------------------
# JWT TOKEN MANAGEMENT
# -------------------------------------------------------------

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.jwt_access_token_expire_minutes)

    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session token has expired. Please sign in again.",
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials.",
        )


# -------------------------------------------------------------
# USER AUTHENTICATION & DEPENDENCIES
# -------------------------------------------------------------

def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security_bearer),
    db: Session = Depends(get_db),
) -> User:
    """Dependency: Extract and validate user from Bearer JWT token."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(credentials.credentials)
    username = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload.",
        )

    user = db.scalar(
        select(User).where(func.lower(User.username) == username.lower())
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact an administrator.",
        )

    return user


def get_optional_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security_bearer),
    db: Session = Depends(get_db),
) -> User | None:
    """Dependency: Extract user from Bearer JWT token if present, otherwise None."""
    if not credentials or not credentials.credentials:
        return None
    try:
        payload = decode_access_token(credentials.credentials)
        username = payload.get("sub")
        if not username:
            return None
        user = db.scalar(
            select(User).where(func.lower(User.username) == username.lower())
        )
        if user and not user.is_active:
            return None
        return user
    except Exception:
        return None


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Dependency: Requires Admin or Super Admin role."""
    if current_user.role not in ("admin", "super_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required to perform this action.",
        )
    return current_user


def require_super_admin(current_user: User = Depends(get_current_user)) -> User:
    """Dependency: Requires Super Admin (Developer) role."""
    if current_user.role != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super Administrator access required.",
        )
    return current_user


# -------------------------------------------------------------
# NOTIFICATION GATEWAY SETTINGS (EMAIL SMTP & SMS GATEWAY)
# -------------------------------------------------------------

NOTIFICATION_CONFIG_PATH = Path(__file__).resolve().parents[2] / "notification_settings.json"


def get_notification_settings() -> dict:
    """Return active SMTP Email and SMS Gateway configuration."""
    defaults = {
        "smtp_host": settings.smtp_host or "",
        "smtp_port": int(settings.smtp_port or 587),
        "smtp_user": settings.smtp_user or "",
        "smtp_password": settings.smtp_password or "",
        "smtp_from_email": settings.smtp_from_email or "noreply@netops.local",
        "sms_provider": settings.sms_provider or "africastalking",
        "sms_api_key": settings.sms_api_key or "",
        "sms_username": settings.sms_username or "",
        "sms_sender_id": settings.sms_sender_id or "",
        "sms_webhook_url": settings.sms_webhook_url or "",
    }
    if NOTIFICATION_CONFIG_PATH.exists():
        try:
            saved = json.loads(NOTIFICATION_CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(saved, dict):
                for k, v in saved.items():
                    if v is not None and k in defaults:
                        defaults[k] = v
        except Exception as exc:
            logger.warning(f"Failed to read notification_settings.json: {exc}")
    return defaults


def save_notification_settings(new_cfg: dict) -> dict:
    """Persist SMTP Email and SMS Gateway configuration to disk."""
    current = get_notification_settings()
    for k in current.keys():
        if k in new_cfg and new_cfg[k] is not None:
            # Keep existing password/api_key if masked placeholder passed
            if k in ("smtp_password", "sms_api_key") and new_cfg[k] == "••••••••":
                continue
            current[k] = new_cfg[k]
    NOTIFICATION_CONFIG_PATH.write_text(json.dumps(current, indent=2), encoding="utf-8")
    return current


def send_email_message(to_email: str, subject: str, html_body: str, plain_body: str = "") -> tuple[bool, str]:
    """Dispatch an HTML email via configured SMTP server (supports STARTTLS 587 & SSL 465)."""
    cfg = get_notification_settings()
    host = (cfg.get("smtp_host") or "").strip()
    port = int(cfg.get("smtp_port") or 587)
    user = (cfg.get("smtp_user") or "").strip()
    password = (cfg.get("smtp_password") or "").strip()
    if "gmail.com" in host.lower():
        password = password.replace(" ", "")
    from_email = (cfg.get("smtp_from_email") or user or "noreply@netops.local").strip()

    if not host:
        return (
            False,
            "SMTP Email Server is not configured yet. Configure SMTP in Settings → Email & SMS Gateways.",
        )

    # Support HTTPS Email Relay / Google Apps Script Web App over TCP 443 (bypasses ISP Port 587 blocks)
    if host.startswith("https://") or host.startswith("http://"):
        try:
            payload = json.dumps({
                "to": to_email,
                "subject": subject,
                "htmlBody": html_body,
                "textBody": plain_body,
                "from": from_email,
                "secret": password,
            }).encode("utf-8")
            req = urllib.request.Request(
                host,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return True, f"Email successfully delivered via HTTPS (Port 443) to {to_email}"
        except Exception as exc:
            return False, f"HTTPS Email Relay error: {exc}"

    try:
        import socket
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_email
        msg["To"] = to_email
        if plain_body:
            msg.attach(MIMEText(plain_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        # Prefer IPv4 address when IPv6 routing is unavailable on the host
        connect_host = host
        try:
            connect_host = socket.gethostbyname(host)
        except Exception:
            connect_host = host

        if port == 465:
            with smtplib.SMTP_SSL(connect_host, port, timeout=12) as server:
                if user and password:
                    server.login(user, password)
                server.sendmail(from_email, [to_email], msg.as_string())
        else:
            with smtplib.SMTP(connect_host, port, timeout=12) as server:
                server.ehlo()
                if port in (587, 2525) or (user and password):
                    server.starttls()
                    server.ehlo()
                if user and password:
                    server.login(user, password)
                server.sendmail(from_email, [to_email], msg.as_string())

        return True, f"Email successfully delivered via {host}:{port} to {to_email}"
    except Exception as exc:
        logger.error(f"Failed to send email via SMTP ({host}:{port}) to {to_email}: {exc}")
        err_str = str(exc)
        if "timed out" in err_str.lower() and port in (25, 465, 587):
            return (
                False,
                f"SMTP connection to {host}:{port} timed out because your local ISP blocks outbound SMTP ports (25/465/587). "
                f"Your Gmail credentials are saved and will work automatically when hosted online, or you can use Port 2525 (e.g. smtp-relay.brevo.com:2525) or Africa's Talking SMS (which uses HTTPS port 443, currently open).",
            )
        return False, f"SMTP delivery error ({host}:{port}): {exc}"


def send_sms_message(phone_number: str, message_text: str) -> tuple[bool, str]:
    """Dispatch an SMS via Africa's Talking, Twilio, or Custom HTTP Webhook."""
    cfg = get_notification_settings()
    provider = (cfg.get("sms_provider") or "africastalking").strip().lower()
    api_key = (cfg.get("sms_api_key") or "").strip()
    username = (cfg.get("sms_username") or "").strip()
    sender_id = (cfg.get("sms_sender_id") or "").strip()
    webhook_url = (cfg.get("sms_webhook_url") or "").strip()

    clean_phone = phone_number.strip()
    if clean_phone.startswith("07") or clean_phone.startswith("01"):
        # Default Kenyan local format 07XX / 01XX -> +2547XX / +2541XX
        clean_phone = "+254" + clean_phone[1:]

    if provider == "africastalking":
        if not api_key or not username:
            return (
                False,
                "Africa's Talking SMS API Key & Username are not configured yet in Settings → Email & SMS Gateways.",
            )
        url = (
            "https://api.sandbox.africastalking.com/version1/messaging"
            if username.lower() == "sandbox"
            else "https://api.africastalking.com/version1/messaging"
        )
        form_data = {
            "username": username,
            "to": clean_phone,
            "message": message_text,
        }
        if sender_id:
            form_data["from"] = sender_id
        encoded = urllib.parse.urlencode(form_data).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=encoded,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "apiKey": api_key,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                resp_body = resp.read().decode("utf-8", errors="ignore")
                return True, f"SMS dispatched via Africa's Talking to {clean_phone} ({resp_body[:120]})"
        except Exception as exc:
            logger.error(f"Africa's Talking SMS error to {clean_phone}: {exc}")
            return False, f"Africa's Talking SMS error: {exc}"

    elif provider == "twilio":
        if not username or not api_key or not sender_id:
            return (
                False,
                "Twilio Account SID, Auth Token, and From Phone Number are required in Settings → Email & SMS Gateways.",
            )
        url = f"https://api.twilio.com/2010-04-01/Accounts/{username}/Messages.json"
        form_data = urllib.parse.urlencode({
            "To": clean_phone,
            "From": sender_id,
            "Body": message_text,
        }).encode("utf-8")
        import base64
        basic_auth = base64.b64encode(f"{username}:{api_key}".encode("utf-8")).decode("ascii")
        req = urllib.request.Request(
            url,
            data=form_data,
            headers={
                "Authorization": f"Basic {basic_auth}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                return True, f"SMS dispatched via Twilio to {clean_phone}"
        except Exception as exc:
            logger.error(f"Twilio SMS error to {clean_phone}: {exc}")
            return False, f"Twilio SMS error: {exc}"

    elif provider == "webhook":
        if not webhook_url:
            return (
                False,
                "Custom SMS Webhook URL is not configured in Settings → Email & SMS Gateways.",
            )
        payload = json.dumps({
            "to": clean_phone,
            "phone": clean_phone,
            "message": message_text,
            "sender_id": sender_id,
        }).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
            headers["X-API-Key"] = api_key
        req = urllib.request.Request(webhook_url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                return True, f"SMS dispatched via Custom Webhook to {clean_phone}"
        except Exception as exc:
            logger.error(f"Webhook SMS error to {clean_phone}: {exc}")
            return False, f"Webhook SMS error: {exc}"

    return False, f"Unsupported or unconfigured SMS provider: {provider}"


# -------------------------------------------------------------
# ACTIVATION LINK & EMAIL DISPATCH
# -------------------------------------------------------------

def generate_activation_token() -> str:
    return secrets.token_urlsafe(32)


def generate_activation_link(token: str) -> str:
    base = settings.frontend_base_url.rstrip("/")
    return f"{base}/login?activation_token={token}"


def send_activation_email(
    email: str,
    username: str,
    login_link: str,
    initial_password: str | None = None,
) -> bool:
    """Send activation email with login link. Logs clearly for testing."""
    logger.info(
        f"[AUTH-EMAIL] Sending activation link to {email} for user '{username}':\n"
        f"  Link: {login_link}\n"
        f"  Temporary Password: {initial_password or '(Set by Admin)'}"
    )

    html_body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background-color: #0b1120; color: #f8fafc; padding: 24px;">
        <div style="max-width: 500px; margin: 0 auto; background: #1e293b; padding: 24px; border-radius: 8px; border: 1px solid #334155;">
            <h2 style="color: #38bdf8; margin-top: 0;">NETOPS Access Invitation</h2>
            <p>Hello <strong>{username}</strong>,</p>
            <p>An administrator has created your NETOPS account. Click the button below to activate your access and proceed to login:</p>
            <div style="text-align: center; margin: 24px 0;">
                <a href="{login_link}" style="background: #2563eb; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
                    Access NETOPS Portal
                </a>
            </div>
            <p style="font-size: 13px; color: #94a3b8;">
                If the button does not work, copy and paste this link into your browser:<br/>
                <a href="{login_link}" style="color: #60a5fa;">{login_link}</a>
            </p>
            {f"<p style='font-size: 13px; color: #cbd5e1;'>Temporary Password: <code>{initial_password}</code></p>" if initial_password else ""}
        </div>
    </body>
    </html>
    """
    ok, _ = send_email_message(
        to_email=email,
        subject="Welcome to NETOPS - Your Account Access Link",
        html_body=html_body,
        plain_body=f"Hello {username}, activate your NETOPS account here: {login_link}",
    )
    return ok


# -------------------------------------------------------------
# OTP FORGOT PASSWORD SERVICE (5-MINUTE EXPIRY)
# -------------------------------------------------------------

OTP_EXPIRY_MINUTES = 5


def generate_otp_code() -> str:
    """Generate a secure 6-digit numeric OTP."""
    return f"{secrets.randbelow(900000) + 100000:06d}"


def create_and_send_password_reset_otp(
    db: Session,
    user: User,
    channel: str,
) -> tuple[PasswordResetOTP, str]:
    """
    Generate a 6-digit OTP with a strict 5-minute expiration time,
    dispatch it to chosen channel (email or phone), and record it.
    """
    target = user.email if channel == "email" else (user.phone_number or user.email)
    otp_code = generate_otp_code()

    # Invalidate any active, unused OTPs for this user
    existing_otps = db.scalars(
        select(PasswordResetOTP).where(
            PasswordResetOTP.user_id == user.id,
            PasswordResetOTP.is_used == False,
        )
    ).all()
    for old_otp in existing_otps:
        old_otp.is_used = True

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    expires_at = now + timedelta(minutes=OTP_EXPIRY_MINUTES)

    otp_record = PasswordResetOTP(
        user_id=user.id,
        otp_code=otp_code,
        channel=channel,
        target=target,
        expires_at=expires_at,
        is_used=False,
    )
    db.add(otp_record)
    db.commit()
    db.refresh(otp_record)

    logger.info(
        f"[OTP-SERVICE] Generated 5-minute OTP for user '{user.username}' via {channel} to {target}:\n"
        f"  Code: {otp_code}\n"
        f"  Expires: {expires_at.isoformat()} (in {OTP_EXPIRY_MINUTES} minutes)"
    )

    delivered = False
    delivery_detail = ""

    if channel == "email":
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background: #0b1120; color: #f8fafc; padding: 24px;">
            <div style="max-width: 450px; margin: 0 auto; background: #1e293b; padding: 24px; border-radius: 8px; border: 1px solid #334155;">
                <h2 style="color: #f59e0b; margin-top: 0;">NETOPS Password Reset Code</h2>
                <p>Hello <strong>{user.username}</strong>,</p>
                <p>You requested to reset your NETOPS password. Use the following 6-digit One-Time Password (OTP) to proceed:</p>
                <div style="background: #0b1120; padding: 16px; border-radius: 6px; text-align: center; margin: 20px 0;">
                    <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #38bdf8;">{otp_code}</span>
                </div>
                <p style="font-size: 13px; color: #ef4444; font-weight: bold;">
                    ⏰ This OTP expires in exactly {OTP_EXPIRY_MINUTES} minutes.
                </p>
                <p style="font-size: 12px; color: #94a3b8;">If you did not request this, please ignore this message.</p>
            </div>
        </body>
        </html>
        """
        plain_body = (
            f"NETOPS Password Reset Code for {user.username}: {otp_code} "
            f"(Valid for {OTP_EXPIRY_MINUTES} minutes)."
        )
        delivered, delivery_detail = send_email_message(
            to_email=target,
            subject=f"NETOPS Password Reset OTP: {otp_code}",
            html_body=html_body,
            plain_body=plain_body,
        )
    elif channel == "sms":
        sms_text = (
            f"NETOPS Security: Your password reset OTP for '{user.username}' is {otp_code}. "
            f"Expires in {OTP_EXPIRY_MINUTES} minutes."
        )
        delivered, delivery_detail = send_sms_message(
            phone_number=target,
            message_text=sms_text,
        )

    otp_record.delivered = delivered
    otp_record.delivery_detail = delivery_detail
    return otp_record, otp_code


def verify_and_consume_otp(
    db: Session,
    user: User,
    otp_code: str,
) -> bool:
    """Verify that the provided OTP is valid, unused, and not expired."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    otp = db.scalar(
        select(PasswordResetOTP)
        .where(
            PasswordResetOTP.user_id == user.id,
            PasswordResetOTP.otp_code == otp_code.strip(),
            PasswordResetOTP.is_used == False,
        )
        .order_by(PasswordResetOTP.id.desc())
    )

    if not otp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid OTP code. Please check and try again.",
        )

    if now > otp.expires_at:
        otp.is_used = True
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This OTP has expired (5-minute validity window exceeded). Please request a new one.",
        )

    # Mark consumed
    otp.is_used = True
    db.commit()
    return True


# -------------------------------------------------------------
# DEFAULT USER SEEDER
# -------------------------------------------------------------

def seed_default_users(db: Session):
    """Seed initial Developer (Super Admin) and Admin accounts if none exist."""
    super_admin = db.scalar(
        select(User).where(User.role == "super_admin")
    )
    if not super_admin:
        now_dt = datetime.now(timezone.utc).replace(tzinfo=None)
        dev_user = User(
            username="developer",
            email="developer@netops.local",
            phone_number="+254700000000",
            hashed_password=hash_password("Admin@1234"),
            role="super_admin",
            is_active=True,
            is_verified=True,
            password_changed_at=now_dt,
        )
        db.add(dev_user)
        logger.info("Created default Super Admin (Developer): developer / Admin@1234")

    admin_user = db.scalar(
        select(User).where(User.username == "admin")
    )
    if not admin_user:
        now_dt = datetime.now(timezone.utc).replace(tzinfo=None)
        adm = User(
            username="admin",
            email="admin@netops.local",
            phone_number="+254711111111",
            hashed_password=hash_password("Admin@1234"),
            role="admin",
            is_active=True,
            is_verified=True,
            password_changed_at=now_dt,
        )
        db.add(adm)
        logger.info("Created default Admin: admin / Admin@1234")

    db.commit()

    # Seed initial access session history if none exist
    has_sessions = db.scalar(select(UserSession).limit(1))
    if not has_sessions:
        dev_obj = db.scalar(select(User).where(User.username == "developer"))
        admin_obj = db.scalar(select(User).where(User.username == "admin"))
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if dev_obj:
            db.add(
                UserSession(
                    user_id=dev_obj.id,
                    username=dev_obj.username,
                    role=dev_obj.role,
                    ip_address="192.168.0.13",
                    user_agent="Mozilla/5.0 (X11; Linux x86_64) NETOPS/Console",
                    login_at=now - timedelta(hours=2, minutes=30),
                    last_activity_at=now - timedelta(minutes=45),
                    logout_at=now - timedelta(minutes=45),
                    duration_seconds=6300,  # 1h 45m
                    is_active=False,
                )
            )
        if admin_obj:
            db.add(
                UserSession(
                    user_id=admin_obj.id,
                    username=admin_obj.username,
                    role=admin_obj.role,
                    ip_address="192.168.0.101",
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) NETOPS/Console",
                    login_at=now - timedelta(hours=1, minutes=10),
                    last_activity_at=now - timedelta(minutes=20),
                    logout_at=now - timedelta(minutes=20),
                    duration_seconds=3000,  # 50m
                    is_active=False,
                )
            )
        db.commit()
