import logging
import secrets
import smtplib
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
from ..models.user import PasswordResetOTP, User

logger = logging.getLogger("netops.auth")
security_bearer = HTTPBearer(auto_error=False)


# -------------------------------------------------------------
# PASSWORD HASHING
# -------------------------------------------------------------

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

    if not settings.smtp_host:
        return True

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Welcome to NETOPS - Your Account Access Link"
        msg["From"] = settings.smtp_from_email
        msg["To"] = email

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
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
            if settings.smtp_user and settings.smtp_password:
                server.starttls()
                server.login(settings.smtp_user, settings.smtp_password)
            server.sendmail(settings.smtp_from_email, [email], msg.as_string())
        return True
    except Exception as exc:
        logger.error(f"Failed to send email via SMTP to {email}: {exc}")
        return False


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

    # Dispatch via email if channel is email
    if channel == "email" and settings.smtp_host:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"NETOPS Password Reset OTP: {otp_code}"
            msg["From"] = settings.smtp_from_email
            msg["To"] = target

            html_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; background: #0b1120; color: #f8fafc; padding: 24px;">
                <div style="max-width: 450px; margin: 0 auto; background: #1e293b; padding: 24px; border-radius: 8px; border: 1px solid #334155;">
                    <h2 style="color: #f59e0b; margin-top: 0;">Password Reset Code</h2>
                    <p>You requested to reset your password. Use the following One-Time Password (OTP) to proceed:</p>
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
            msg.attach(MIMEText(html_body, "html"))
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
                if settings.smtp_user and settings.smtp_password:
                    server.starttls()
                    server.login(settings.smtp_user, settings.smtp_password)
                server.sendmail(settings.smtp_from_email, [target], msg.as_string())
        except Exception as exc:
            logger.error(f"Failed to dispatch OTP email: {exc}")

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
        dev_user = User(
            username="developer",
            email="developer@netops.local",
            phone_number="+254700000000",
            hashed_password=hash_password("Admin@1234"),
            role="super_admin",
            is_active=True,
            is_verified=True,
        )
        db.add(dev_user)
        logger.info("Created default Super Admin (Developer): developer / Admin@1234")

    admin_user = db.scalar(
        select(User).where(User.username == "admin")
    )
    if not admin_user:
        adm = User(
            username="admin",
            email="admin@netops.local",
            phone_number="+254711111111",
            hashed_password=hash_password("Admin@1234"),
            role="admin",
            is_active=True,
            is_verified=True,
        )
        db.add(adm)
        logger.info("Created default Admin: admin / Admin@1234")

    db.commit()
