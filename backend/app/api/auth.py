from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.user import User
from ..services.auth_service import (
    create_access_token,
    create_and_send_password_reset_otp,
    get_current_user,
    hash_password,
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


# -------------------------------------------------------------
# SCHEMAS
# -------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


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

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters long")
        return v


# -------------------------------------------------------------
# LOGIN
# -------------------------------------------------------------

@router.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate user with username or email and return JWT bearer token."""
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

    access_token = create_access_token(
        data={
            "sub": user.username,
            "role": user.role,
            "user_id": user.id,
            "email": user.email,
        }
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
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
# CURRENT USER INFO
# -------------------------------------------------------------

@router.get("/me")
def get_my_profile(current_user: User = Depends(get_current_user)):
    """Return currently authenticated user profile."""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "phone_number": current_user.phone_number,
        "role": current_user.role,
        "is_verified": current_user.is_verified,
    }


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
    """Find user and return masked email & phone channels for OTP dispatch."""
    ident = req.identifier.strip().lower()

    user = db.scalar(
        select(User).where(
            or_(
                func.lower(User.username) == ident,
                func.lower(User.email) == ident,
            )
        )
    )

    if not user:
        # Return generic error to avoid user enumeration
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account found matching this identifier.",
        )

    return {
        "username": user.username,
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
    ident = req.identifier.strip().lower()

    user = db.scalar(
        select(User).where(
            or_(
                func.lower(User.username) == ident,
                func.lower(User.email) == ident,
            )
        )
    )

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

    return {
        "status": "otp_sent",
        "channel": req.channel,
        "target": target_display,
        "expires_in_minutes": 5,
        "message": f"A 6-digit OTP has been sent via {req.channel.upper()} to {target_display}. It expires in exactly 5 minutes.",
        # For seamless local development/testing without real SMS gateway:
        "dev_otp_preview": otp_code,
    }


# -------------------------------------------------------------
# FORGOT PASSWORD: STEP 3 - VERIFY OTP & RESET PASSWORD
# -------------------------------------------------------------

@router.post("/forgot-password/reset")
def reset_password(
    req: ResetPasswordRequest,
    db: Session = Depends(get_db),
):
    """Validate 5-minute OTP and reset password."""
    ident = req.identifier.strip().lower()

    user = db.scalar(
        select(User).where(
            or_(
                func.lower(User.username) == ident,
                func.lower(User.email) == ident,
            )
        )
    )

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
