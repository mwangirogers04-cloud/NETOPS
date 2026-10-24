from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.user import User, UserSession
from ..services.event_service import create_event
from ..services.auth_service import (
    check_user_conflicts,
    create_access_token,
    create_and_send_password_reset_otp,
    decode_access_token,
    generate_activation_link,
    generate_activation_token,
    get_current_user,
    get_notification_settings,
    hash_password,
    normalize_phone_number,
    require_admin,
    save_notification_settings,
    security_bearer,
    send_activation_email,
    send_email_message,
    send_sms_message,
    validate_password_complexity,
    verify_and_consume_otp,
    verify_password,
)

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


def mask_string(val: str | None, is_email: bool = False) -> str | None:
    if not val:
        return None
    if is_email and "@" in val:
        name, domain = val.split("@", 1)
        if len(name) <= 2:
            masked_name = name[0] + "***"
        else:
            masked_name = name[0] + "***" + name[-1]
        return f"{masked_name}@{domain}"
    else:
        clean = val.strip()
        if len(clean) <= 4:
            return "***" + clean[-1:]
        return clean[:3] + "***" + clean[-3:]


PASSWORD_EXPIRY_DAYS = 90  # Passwords expire after 3 months (90 days)


def is_password_expired(user: User, current_datetime: datetime | None = None) -> bool:
    """
    Check if a user's password has expired (policy: every 3 months / 90 days).
    Policy Rules:
      1. Developers ('super_admin'): Password NEVER expires.
      2. Administrators ('admin'): Expires after 3 months (admins are permitted to reset their own passwords).
      3. Standard Users ('user'): Expires after 3 months (standard users cannot self-reset; must contact admin/developer).
    """
    if user.role == "super_admin":
        return False

    now = current_datetime or datetime.now(timezone.utc).replace(tzinfo=None)
    changed_at = getattr(user, "password_changed_at", None) or getattr(user, "created_at", None) or now

    return (now - changed_at).total_seconds() > (PASSWORD_EXPIRY_DAYS * 86400)


def get_password_expiry_info(user: User, current_datetime: datetime | None = None) -> dict:
    """Return comprehensive password expiration metadata for a given user."""
    if user.role == "super_admin":
        return {
            "expires": False,
            "is_expired": False,
            "days_remaining": None,
            "expires_at": None,
            "must_change": False,
            "can_self_reset": True,
            "policy": "Developer passwords do not expire",
            "message": "Developer passwords do not expire.",
        }

    now = current_datetime or datetime.now(timezone.utc).replace(tzinfo=None)
    changed_at = getattr(user, "password_changed_at", None) or getattr(user, "created_at", None) or now
    age_seconds = (now - changed_at).total_seconds()
    expiry_seconds = PASSWORD_EXPIRY_DAYS * 86400
    is_expired = age_seconds > expiry_seconds
    remaining_seconds = max(0, expiry_seconds - age_seconds)
    days_remaining = int(remaining_seconds // 86400)
    expires_at = changed_at + timedelta(days=PASSWORD_EXPIRY_DAYS)

    can_self_reset = user.role in ("admin", "super_admin")

    return {
        "expires": True,
        "is_expired": is_expired,
        "days_remaining": days_remaining if not is_expired else 0,
        "expires_at": expires_at.isoformat(),
        "must_change": is_expired,
        "can_self_reset": can_self_reset,
        "policy": "Passwords expire every 3 months (90 days)",
        "message": (
            "Password has expired after 3 months."
            if is_expired
            else f"Password expires in {days_remaining} day{'s' if days_remaining != 1 else ''}."
        ),
    }


def _find_user_by_identifier(db: Session, identifier: str) -> User | None:
    """Find a user by username, email address, or phone number (raw or normalized)."""
    ident = (identifier or "").strip()
    if not ident:
        return None
    ident_lower = ident.lower()
    user = db.scalar(
        select(User).where(
            or_(
                func.lower(User.username) == ident_lower,
                func.lower(User.email) == ident_lower,
                User.phone_number == ident,
            )
        )
    )
    if user:
        return user

    norm_phone = normalize_phone_number(ident)
    if norm_phone:
        for candidate in db.scalars(select(User)).all():
            if candidate.phone_number and normalize_phone_number(candidate.phone_number) == norm_phone:
                return candidate
    return None


# -------------------------------------------------------------
# SCHEMAS
# -------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


class CheckAvailabilityRequest(BaseModel):
    username: str | None = None
    email: str | None = None
    phone_number: str | None = None
    exclude_user_id: int | None = None


class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    phone_number: str
    password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        clean = v.strip()
        if len(clean) < 3:
            raise ValueError("Username must be at least 3 characters")
        return clean

    @field_validator("phone_number")
    @classmethod
    def validate_phone(cls, v: str) -> str:
        clean = v.strip()
        if len(clean) < 7:
            raise ValueError("Please provide a valid phone number")
        return clean


class ActivateRequest(BaseModel):
    activation_token: str


class ForgotPasswordChannelRequest(BaseModel):
    identifier: str


class SendOtpRequest(BaseModel):
    identifier: str
    channel: str  # "email" or "sms"

    @field_validator("channel")
    @classmethod
    def validate_channel(cls, v: str) -> str:
        clean = v.strip().lower()
        if clean not in ("email", "sms"):
            raise ValueError("Channel must be 'email' or 'sms'")
        return clean


class ResetPasswordRequest(BaseModel):
    identifier: str
    otp_code: str
    new_password: str


class AdminDirectResetPasswordRequest(BaseModel):
    target_identifier: str
    new_password: str
    admin_identifier: str | None = None
    admin_password: str | None = None

    @field_validator("target_identifier")
    @classmethod
    def validate_target_identifier(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Please provide the username, email, or phone number of the user to reset")
        return clean


class ChangeExpiredPasswordRequest(BaseModel):
    identifier: str
    current_password: str
    new_password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


# -------------------------------------------------------------
# CHECK EMAIL / PHONE / USERNAME AVAILABILITY & SELF-REGISTER
# -------------------------------------------------------------

@router.post("/check-availability")
def check_account_availability(
    req: CheckAvailabilityRequest,
    db: Session = Depends(get_db),
):
    """Recheck whether an email address, phone number, or username already exists."""
    return check_user_conflicts(
        db=db,
        username=req.username,
        email=req.email,
        phone_number=req.phone_number,
        exclude_user_id=req.exclude_user_id,
    )


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register_account(
    req: RegisterRequest,
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials | None = Depends(security_bearer),
):
    """
    Register a new user account.
    Public self-registration is disabled. Only Administrators and Developers
    can register accounts.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public self-registration is disabled. Accounts can only be created by an Administrator or Developer.",
        )

    authorizer = get_current_user(credentials=credentials, db=db)
    if authorizer.role not in ("admin", "super_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public self-registration is disabled. Accounts can only be created by an Administrator or Developer.",
        )
    clean_username = req.username.strip()
    clean_email = str(req.email).strip().lower()
    clean_phone = req.phone_number.strip()

    try:
        validate_password_complexity(req.password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    conflicts = check_user_conflicts(
        db=db,
        username=clean_username,
        email=clean_email,
        phone_number=clean_phone,
    )
    if not conflicts["available"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=conflicts["detail"],
        )

    token = generate_activation_token()
    login_link = generate_activation_link(token)

    new_user = User(
        username=clean_username,
        email=clean_email,
        phone_number=clean_phone,
        hashed_password=hash_password(req.password),
        role="user",
        is_active=True,
        is_verified=True,
        activation_token=None,
        password_changed_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    send_activation_email(
        email=new_user.email,
        username=new_user.username,
        login_link=login_link,
    )

    return {
        "status": "registered",
        "message": f"Account '{new_user.username}' registered successfully! You can now sign in.",
        "user": {
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "phone_number": new_user.phone_number,
            "role": new_user.role,
            "is_verified": new_user.is_verified,
        },
    }


# -------------------------------------------------------------
# LOGIN
# -------------------------------------------------------------

FAILED_LOGIN_ATTEMPTS: dict[str, int] = {}


def clear_failed_login_attempts(identifier: str | None = None):
    """Reset failed login attempts counter for an identifier or all users."""
    if identifier:
        ident = identifier.strip().lower()
        FAILED_LOGIN_ATTEMPTS.pop(ident, None)
    else:
        FAILED_LOGIN_ATTEMPTS.clear()


@router.post("/login")
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Authenticate user with username or email, record session, and return JWT bearer token."""
    ident = req.username.strip().lower()

    # Block if already reached 3 failed attempts
    if FAILED_LOGIN_ATTEMPTS.get(ident, 0) >= 3:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You have entered an incorrect password 3 times. Please contact the administrator.",
        )

    user = db.scalar(
        select(User).where(
            or_(
                func.lower(User.username) == ident,
                func.lower(User.email) == ident,
            )
        )
    )

    if not user or not verify_password(req.password, user.hashed_password):
        current_fails = FAILED_LOGIN_ATTEMPTS.get(ident, 0) + 1
        FAILED_LOGIN_ATTEMPTS[ident] = current_fails
        if user:
            if user.username:
                FAILED_LOGIN_ATTEMPTS[user.username.lower()] = current_fails
            if user.email:
                FAILED_LOGIN_ATTEMPTS[user.email.lower()] = current_fails

        if current_fails >= 3:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="You have entered an incorrect password 3 times. Please contact the administrator.",
            )

        remaining = 3 - current_fails
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Incorrect username or password. ({remaining} attempt{'s' if remaining > 1 else ''} remaining)",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is currently deactivated. Contact your administrator.",
        )

    # 3-Month Password Expiration Policy (90 Days)
    # Policy rules:
    #   1. Developers ('super_admin'): Password NEVER expires.
    #   2. Administrators ('admin'): Expires after 3 months; admins can reset their own password.
    #   3. Standard Users ('user'): Expires after 3 months; standard users cannot self-reset and must contact an administrator or developer.
    if is_password_expired(user):
        if user.role == "user":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your password has expired after 3 months. Standard users are required to contact the Administrator or Developer to reset the password.",
                headers={"X-Password-Expired": "user"},
            )
        elif user.role == "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your Administrator password has expired after 3 months. Please reset or update your password to continue.",
                headers={"X-Password-Expired": "admin"},
            )

    # Success: reset failed attempts counter
    clear_failed_login_attempts(ident)
    if user.username:
        clear_failed_login_attempts(user.username)
    if user.email:
        clear_failed_login_attempts(user.email)

    # Record User Access Session
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    client_ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "127.0.0.1")
    )
    user_agent = request.headers.get("user-agent", "Unknown")[:250]

    session = UserSession(
        user_id=user.id,
        username=user.username,
        role=user.role,
        ip_address=client_ip,
        user_agent=user_agent,
        login_at=now,
        last_activity_at=now,
        duration_seconds=0,
        is_active=True,
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    access_token = create_access_token(
        data={
            "sub": user.username,
            "role": user.role,
            "user_id": user.id,
            "email": user.email,
            "session_id": session.id,
        }
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "session_id": session.id,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "phone_number": user.phone_number,
            "role": user.role,
            "is_verified": user.is_verified,
            "password_expiry": get_password_expiry_info(user),
        },
    }


# -------------------------------------------------------------
# CURRENT USER INFO & SESSION HEARTBEAT
# -------------------------------------------------------------

@router.get("/me")
def get_my_profile(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return currently authenticated user profile and refresh active session duration."""
    active_session = db.scalar(
        select(UserSession)
        .where(UserSession.user_id == current_user.id, UserSession.is_active == True)
        .order_by(UserSession.login_at.desc())
    )
    if active_session:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        # Enforce 3-minute inactivity timeout (180 seconds)
        if active_session.last_activity_at and (now - active_session.last_activity_at).total_seconds() > 180:
            active_session.is_active = False
            active_session.logout_at = now
            active_session.duration_seconds = max(1, int((now - active_session.login_at).total_seconds()))
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired due to 3 minutes of inactivity.",
            )
        active_session.last_activity_at = now
        active_session.duration_seconds = max(1, int((now - active_session.login_at).total_seconds()))
        db.commit()

    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "phone_number": current_user.phone_number,
        "role": current_user.role,
        "is_verified": current_user.is_verified,
        "password_expiry": get_password_expiry_info(current_user),
    }


@router.post("/heartbeat")
def session_heartbeat(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Heartbeat invoked while user is active on the dashboard to track session duration."""
    active_session = db.scalar(
        select(UserSession)
        .where(UserSession.user_id == current_user.id, UserSession.is_active == True)
        .order_by(UserSession.login_at.desc())
    )
    if active_session:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        # Enforce 3-minute inactivity timeout (180 seconds)
        if active_session.last_activity_at and (now - active_session.last_activity_at).total_seconds() > 180:
            active_session.is_active = False
            active_session.logout_at = now
            active_session.duration_seconds = max(1, int((now - active_session.login_at).total_seconds()))
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired due to 3 minutes of inactivity.",
            )
        active_session.last_activity_at = now
        active_session.duration_seconds = max(1, int((now - active_session.login_at).total_seconds()))
        db.commit()
        return {
            "status": "ok",
            "session_id": active_session.id,
            "duration_seconds": active_session.duration_seconds,
        }
    return {"status": "no_active_session"}


@router.post("/logout")
def logout_user(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Log out user and finalize access session duration."""
    active_sessions = db.scalars(
        select(UserSession)
        .where(UserSession.user_id == current_user.id, UserSession.is_active == True)
    ).all()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for s in active_sessions:
        s.logout_at = now
        s.last_activity_at = now
        s.duration_seconds = max(1, int((now - s.login_at).total_seconds()))
        s.is_active = False
    db.commit()
    return {"status": "logged_out", "message": "Session successfully closed."}


# -------------------------------------------------------------
# ACTIVATION LINK
# -------------------------------------------------------------

@router.post("/activate")
def activate_account(req: ActivateRequest, db: Session = Depends(get_db)):
    """Activate user account via link token sent upon creation."""
    token = req.activation_token.strip()
    user = db.scalar(
        select(User).where(User.activation_token == token)
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user.is_verified = True
    user.activation_token = None
    user.password_changed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()

    return {
        "status": "activated",
        "username": user.username,
        "email": user.email,
        "message": "Account successfully activated! Please sign in with your credentials.",
    }


# -------------------------------------------------------------
# FORGOT PASSWORD: STEP 1 - GET CHANNELS
# -------------------------------------------------------------

@router.post("/forgot-password/channels")
def get_reset_channels(
    req: ForgotPasswordChannelRequest,
    db: Session = Depends(get_db),
):
    """Find user and return masked email & phone channels for OTP dispatch or Admin/Developer reset."""
    user = _find_user_by_identifier(db, req.identifier)

    if not user:
        # Return generic error to avoid user enumeration
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account found matching this identifier.",
        )

    if user.role not in ("admin", "super_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Standard users cannot reset passwords independently. Please contact an Administrator or Developer to reset your password.",
        )

    return {
        "username": user.username,
        "role": user.role,
        "email_masked": mask_string(user.email, is_email=True),
        "phone_masked": mask_string(user.phone_number, is_email=False),
        "has_email": bool(user.email),
        "has_phone": bool(user.phone_number),
    }


# -------------------------------------------------------------
# FORGOT PASSWORD: STEP 2 - SEND 5-MINUTE OTP
# -------------------------------------------------------------

@router.post("/forgot-password/send-otp")
def send_reset_otp(
    req: SendOtpRequest,
    db: Session = Depends(get_db),
):
    """Generate and dispatch a 5-minute OTP to chosen channel."""
    user = _find_user_by_identifier(db, req.identifier)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User account not found.",
        )

    if user.role not in ("admin", "super_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Standard users cannot reset passwords independently. Please contact an Administrator or Developer to reset your password.",
        )

    if req.channel == "sms" and not user.phone_number:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User does not have a registered phone number. Please choose Email.",
        )

    otp_record, otp_code = create_and_send_password_reset_otp(
        db, user, req.channel
    )

    target_display = (
        mask_string(user.email, is_email=True)
        if req.channel == "email"
        else mask_string(user.phone_number, is_email=False)
    )
    delivered = bool(getattr(otp_record, "delivered", False))
    delivery_detail = getattr(otp_record, "delivery_detail", "")

    if delivered:
        msg = f"A 6-digit OTP has been sent via {req.channel.upper()} to {target_display}. It expires in 5 minutes."
    else:
        msg = (
            f"6-digit OTP generated for {target_display} (valid for 5 minutes). "
            f"Use the OTP code displayed below, or configure your {req.channel.upper()} gateway in Settings → Email & SMS OTP Gateways for external delivery."
        )

    return {
        "status": "otp_sent",
        "channel": req.channel,
        "target": target_display,
        "delivered": delivered,
        "delivery_detail": delivery_detail,
        "expires_in_minutes": 5,
        "message": msg,
        "dev_otp_preview": otp_code,
    }


# -------------------------------------------------------------
# NOTIFICATION GATEWAY SETTINGS (ADMIN)
# -------------------------------------------------------------

class NotificationSettingsUpdate(BaseModel):
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


class NotificationTestRequest(BaseModel):
    channel: str  # "email" or "sms"
    recipient: str


@router.get("/notification-settings")
def read_notification_settings(current_user: User = Depends(require_admin)):
    """Get current Email (SMTP) and SMS Gateway settings (masking secrets)."""
    cfg = get_notification_settings()
    return {
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


@router.post("/notification-settings")
def update_notification_settings(
    req: NotificationSettingsUpdate,
    current_user: User = Depends(require_admin),
):
    """Save Email (SMTP) and SMS Gateway settings."""
    saved = save_notification_settings(req.model_dump())
    return {
        "status": "saved",
        "message": "Email (SMTP) & SMS OTP Gateway settings saved successfully.",
        "smtp_configured": bool(saved.get("smtp_host")),
        "sms_configured": bool(saved.get("sms_api_key") or saved.get("sms_webhook_url")),
    }


@router.post("/notification-settings/test")
def test_notification_gateway(
    req: NotificationTestRequest,
    current_user: User = Depends(require_admin),
):
    """Send a live test Email or SMS using the configured gateway."""
    ch = req.channel.strip().lower()
    recipient = req.recipient.strip()
    if not recipient:
        raise HTTPException(status_code=400, detail="Please enter a recipient email or phone number.")

    if ch == "email":
        ok, detail = send_email_message(
            to_email=recipient,
            subject="NETOPS SMTP Gateway Test",
            html_body=(
                "<div style='font-family:sans-serif;padding:20px;background:#0f172a;color:#f8fafc;border-radius:8px;'>"
                "<h3 style='color:#38bdf8;'>✅ NETOPS Email Gateway Connected</h3>"
                "<p>Your SMTP server is properly configured to deliver Password Reset OTPs and Account Activation links.</p>"
                "</div>"
            ),
            plain_body="NETOPS Email Gateway Connected: Your SMTP server is properly configured.",
        )
    elif ch == "sms":
        ok, detail = send_sms_message(
            phone_number=recipient,
            message_text="NETOPS SMS Gateway Test: Your SMS provider is properly configured to deliver 5-minute OTP codes.",
        )
    else:
        raise HTTPException(status_code=400, detail="Channel must be 'email' or 'sms'.")

    return {
        "delivered": ok,
        "channel": ch,
        "recipient": recipient,
        "detail": detail,
    }


# -------------------------------------------------------------
# FORGOT PASSWORD: STEP 3 - VERIFY OTP & RESET PASSWORD
# -------------------------------------------------------------

@router.post("/forgot-password/reset")
def reset_password(
    req: ResetPasswordRequest,
    db: Session = Depends(get_db),
):
    """Validate 5-minute OTP and reset password (enforcing 8+ chars, uppercase, lowercase, special char)."""
    try:
        validate_password_complexity(req.new_password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    user = _find_user_by_identifier(db, req.identifier)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User account not found.",
        )

    if user.role not in ("admin", "super_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Standard users cannot reset passwords independently. Please contact an Administrator or Developer to reset your password.",
        )

    # Verify and consume OTP (strictly validates 5-minute expiry)
    verify_and_consume_otp(db, user, req.otp_code)

    # Update password
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    user.hashed_password = hash_password(req.new_password)
    user.password_changed_at = now
    user.is_verified = True  # Verified via OTP
    db.commit()

    create_event(
        db=db,
        event_type="password_reset",
        message=f"Password for user '{user.username}' reset via OTP verification by user '{user.username}'.",
        device_id=None,
        actor=user.username,
    )
    db.commit()

    clear_failed_login_attempts(user.username)
    clear_failed_login_attempts(user.email)

    return {
        "status": "password_reset_success",
        "username": user.username,
        "message": "Password successfully reset! You can now log in with your new password.",
    }


# -------------------------------------------------------------
# ADMIN / DEVELOPER DIRECT PASSWORD RESET (NO OTP REQUIRED)
# -------------------------------------------------------------

@router.post("/forgot-password/admin-reset")
@router.post("/admin-reset-password")
def admin_direct_reset_password(
    req: AdminDirectResetPasswordRequest,
    credentials=Depends(security_bearer),
    db: Session = Depends(get_db),
):
    """
    Directly reset a user's password using Administrative ('admin') or
    Developer ('super_admin') rights without sending an OTP to phone or email.
    Rules enforced:
      1. Authorizer must have 'admin' or 'super_admin' rights.
      2. An 'admin' CANNOT reset the password of the Developer ('super_admin').
      3. New password must be >= 8 characters and include at least 1 uppercase letter,
         1 lowercase letter, and 1 special character.
    """
    authorizer: User | None = None

    # 1. If explicit Admin / Developer credentials were provided on the Login page, verify them first
    if req.admin_identifier and req.admin_identifier.strip():
        if not req.admin_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Please enter the Administrator or Developer password to authorize this reset.",
            )
        candidate = _find_user_by_identifier(db, req.admin_identifier.strip())
        if not candidate or not verify_password(req.admin_password, candidate.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Administrator or Developer credentials. Please check your username/email and password.",
            )
        authorizer = candidate
    elif credentials and credentials.credentials:
        # 2. Otherwise check active Bearer token if present
        payload = decode_access_token(credentials.credentials)
        sub_username = payload.get("sub")
        if sub_username:
            authorizer = db.scalar(
                select(User).where(func.lower(User.username) == sub_username.lower())
            )

    if not authorizer:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Please provide valid Administrator or Developer credentials to authorize a direct password reset.",
        )

    if not authorizer.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The authorizing account is currently deactivated.",
        )

    if authorizer.role not in ("admin", "super_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Administrative or Developer rights are required to reset user passwords without an OTP.",
        )

    target_user = _find_user_by_identifier(db, req.target_identifier)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No user account found matching '{req.target_identifier.strip()}'. Please check the username, email, or phone number.",
        )

    # Role hierarchy check: An Administrator (admin) CANNOT reset the Developer (super_admin) password
    if target_user.role == "super_admin" and authorizer.role != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: An Administrator cannot reset the password for the Developer (Super Administrator) account. Only a Developer can reset the Developer password.",
        )

    # Enforce password complexity: >= 8 chars, 1 uppercase, 1 lowercase, 1 special character
    try:
        validate_password_complexity(req.new_password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    target_user.hashed_password = hash_password(req.new_password)
    target_user.password_changed_at = now
    target_user.is_verified = True
    db.commit()

    role_label = (
        "Developer (Super Admin)"
        if authorizer.role == "super_admin"
        else "Administrator"
    )

    create_event(
        db=db,
        event_type="password_reset",
        message=f"Password for user '{target_user.username}' directly reset by {role_label} '{authorizer.username}'.",
        device_id=None,
        actor=authorizer.username,
    )
    db.commit()

    clear_failed_login_attempts(target_user.username)
    clear_failed_login_attempts(target_user.email)

    return {
        "status": "password_reset_success",
        "username": target_user.username,
        "email": target_user.email,
        "role": target_user.role,
        "reset_by": authorizer.username,
        "reset_by_role": authorizer.role,
        "message": (
            f"Password for user '{target_user.username}' has been directly reset by "
            f"{role_label} '{authorizer.username}' (no OTP required). "
            f"'{target_user.username}' can now sign in with the new password."
        ),
    }


# -------------------------------------------------------------
# CHANGE EXPIRED PASSWORD (ADMIN SELF-SERVICE ON EXPIRATION)
# -------------------------------------------------------------

@router.post("/change-expired-password")
def change_expired_password(
    req: ChangeExpiredPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """
    Allow an Administrator (or Developer) to reset their expired password (policy: every 3 months)
    by confirming their current password and providing a new compliant password.
    Standard users are prohibited from self-resetting: they must contact an administrator or developer.
    """
    ident = req.identifier.strip().lower()
    user = _find_user_by_identifier(db, ident)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found. Please check your username or email.",
        )

    if not verify_password(req.current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is currently deactivated. Contact your administrator.",
        )

    # Policy enforcement: Standard users cannot reset their own password when expired
    if user.role not in ("admin", "super_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Standard users cannot reset their own password. "
                "Please contact an Administrator or Developer to reset your password."
            ),
        )

    try:
        validate_password_complexity(req.new_password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    if verify_password(req.new_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from your current password.",
        )

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    user.hashed_password = hash_password(req.new_password)
    user.password_changed_at = now
    user.is_verified = True
    db.commit()

    role_label = (
        "Developer (Super Admin)"
        if user.role == "super_admin"
        else "Administrator"
    )

    create_event(
        db=db,
        event_type="password_reset",
        message=f"Expired password for {role_label} '{user.username}' successfully reset by user '{user.username}'.",
        device_id=None,
        actor=user.username,
    )
    db.commit()

    clear_failed_login_attempts(user.username)
    clear_failed_login_attempts(user.email)

    # Establish an active session and access token
    client_ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "127.0.0.1")
    )
    user_agent = request.headers.get("user-agent", "Unknown")[:250]

    session = UserSession(
        user_id=user.id,
        username=user.username,
        role=user.role,
        ip_address=client_ip,
        user_agent=user_agent,
        login_at=now,
        last_activity_at=now,
        duration_seconds=0,
        is_active=True,
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    access_token = create_access_token(
        data={
            "sub": user.username,
            "role": user.role,
            "user_id": user.id,
            "email": user.email,
            "session_id": session.id,
        }
    )

    return {
        "status": "password_reset_success",
        "message": "Password successfully updated! You are now logged in.",
        "access_token": access_token,
        "token_type": "bearer",
        "session_id": session.id,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "phone_number": user.phone_number,
            "role": user.role,
            "is_verified": user.is_verified,
            "password_expiry": get_password_expiry_info(user),
        },
    }


# -------------------------------------------------------------
# CHANGE PASSWORD (AUTHENTICATED SESSIONS)
# -------------------------------------------------------------

@router.post("/change-password")
def change_my_password(
    req: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Allow an authenticated user to change their password."""
    if not verify_password(req.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )

    # Standard users whose passwords have already expired cannot self-change
    if current_user.role == "user" and is_password_expired(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Your password has expired after 3 months. "
                "Standard users must contact an Administrator or Developer to reset the password."
            ),
        )

    try:
        validate_password_complexity(req.new_password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    if verify_password(req.new_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from your current password.",
        )

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    current_user.hashed_password = hash_password(req.new_password)
    current_user.password_changed_at = now
    db.commit()

    create_event(
        db=db,
        event_type="password_reset",
        message=f"Password for user '{current_user.username}' updated by user '{current_user.username}'.",
        device_id=None,
        actor=current_user.username,
    )
    db.commit()

    return {
        "status": "success",
        "message": "Password changed successfully.",
        "password_expiry": get_password_expiry_info(current_user),
    }
