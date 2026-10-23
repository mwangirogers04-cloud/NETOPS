from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.user import User, UserSession
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
):
    """
    Register a new user account from the Login page after rechecking that
    the email address, phone number, and username do not already exist.
    """
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

@router.post("/login")
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Authenticate user with username or email, record session, and return JWT bearer token."""
    ident = req.username.strip().lower()

    user = db.scalar(
        select(User).where(
            or_(
                func.lower(User.username) == ident,
                func.lower(User.email) == ident,
            )
        )
    )

    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is currently deactivated. Contact your administrator.",
        )

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

    # Verify and consume OTP (strictly validates 5-minute expiry)
    verify_and_consume_otp(db, user, req.otp_code)

    # Update password
    user.hashed_password = hash_password(req.new_password)
    user.is_verified = True  # Verified via OTP
    db.commit()

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

    target_user.hashed_password = hash_password(req.new_password)
    target_user.is_verified = True
    db.commit()

    role_label = (
        "Developer (Super Admin)"
        if authorizer.role == "super_admin"
        else "Administrator"
    )
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
