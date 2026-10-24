from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.user import User
from .auth import clear_failed_login_attempts, get_password_expiry_info
from ..services.event_service import create_event
from ..services.auth_service import (
    check_user_conflicts,
    generate_activation_link,
    generate_activation_token,
    hash_password,
    require_admin,
    send_activation_email,
    validate_password_complexity,
)

router = APIRouter(
    prefix="/users",
    tags=["User Management"],
)


class UserCreateRequest(BaseModel):
    username: str
    email: EmailStr
    phone_number: str
    password: str
    role: str = "user"  # "admin" or "user"

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

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        clean = v.strip().lower()
        if clean not in ("admin", "user"):
            raise ValueError("Role must be 'admin' or 'user'")
        return clean


class UserUpdateRequest(BaseModel):
    username: str | None = None
    email: EmailStr | None = None
    phone_number: str | None = None
    role: str | None = None
    password: str | None = None
    is_active: bool | None = None
    is_verified: bool | None = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str | None) -> str | None:
        if v is not None:
            clean = v.strip()
            if len(clean) < 3:
                raise ValueError("Username must be at least 3 characters")
            return clean
        return v

    @field_validator("phone_number")
    @classmethod
    def validate_phone(cls, v: str | None) -> str | None:
        if v is not None:
            clean = v.strip()
            if len(clean) < 7:
                raise ValueError("Please provide a valid phone number")
            return clean
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str | None) -> str | None:
        if v is not None and v.strip() != "":
            return v
        return None

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str | None) -> str | None:
        if v is not None:
            clean = v.strip().lower()
            if clean not in ("admin", "user", "super_admin"):
                raise ValueError("Role must be 'admin', 'user', or 'super_admin'")
            return clean
        return v


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    phone_number: str | None
    role: str
    is_active: bool
    is_verified: bool
    created_at: datetime
    created_by: str | None = None
    activation_link: str | None = None
    password_changed_at: datetime | None = None
    password_expiry: dict | None = None


# -------------------------------------------------------------
# LIST USERS (ADMIN & SUPER ADMIN)
# -------------------------------------------------------------

@router.get(
    "/",
    response_model=list[UserResponse],
)
def list_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """List all user accounts in NETOPS."""
    users = db.scalars(
        select(User).order_by(User.id.asc())
    ).all()

    results = []
    for u in users:
        link = (
            generate_activation_link(u.activation_token)
            if u.activation_token
            else None
        )
        results.append(
            UserResponse(
                id=u.id,
                username=u.username,
                email=u.email,
                phone_number=u.phone_number,
                role=u.role,
                is_active=u.is_active,
                is_verified=u.is_verified,
                created_at=u.created_at,
                created_by=u.created_by,
                activation_link=link,
                password_changed_at=getattr(u, "password_changed_at", None),
                password_expiry=get_password_expiry_info(u),
            )
        )
    return results


# -------------------------------------------------------------
# CREATE USER (SUPER ADMIN OR ADMIN)
# -------------------------------------------------------------

@router.post(
    "/",
    response_model=dict,
    status_code=status.HTTP_201_CREATED,
)
def create_user(
    req: UserCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Create a new user account requesting username, email, phone number,
    role, and initial credentials. Dispatches an activation login link to their email.
    """
    # Permission check: Only super_admin can create admin accounts
    if req.role == "admin" and current_user.role != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only Super Administrators can create Admin accounts.",
        )

    # Validate initial password complexity (min 8 chars, 1 uppercase, 1 lowercase, 1 special)
    try:
        validate_password_complexity(req.password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    # Check for existing username, email, or phone number
    clean_username = req.username.strip()
    clean_email = str(req.email).strip().lower()
    clean_phone = req.phone_number.strip()

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
        phone_number=req.phone_number.strip(),
        hashed_password=hash_password(req.password),
        role=req.role,
        is_active=True,
        is_verified=False,
        activation_token=token,
        created_by=current_user.username,
        password_changed_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Log user creation audit event
    create_event(
        db=db,
        event_type="user_created",
        message=(
            f"New user '{new_user.username}' (role: {new_user.role}) created by "
            f"{current_user.role} '{current_user.username}'. Activation link dispatched to {new_user.email}."
        ),
        device_id=None,
        actor=current_user.username,
    )
    db.commit()

    # Dispatch email activation link
    send_activation_email(
        email=new_user.email,
        username=new_user.username,
        login_link=login_link,
        initial_password=req.password,
    )

    return {
        "status": "created",
        "message": f"User '{new_user.username}' created successfully. An activation login link has been sent to {new_user.email}.",
        "activation_link": login_link,
        "user": {
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "phone_number": new_user.phone_number,
            "role": new_user.role,
            "is_verified": new_user.is_verified,
            "created_by": new_user.created_by,
        },
    }


# -------------------------------------------------------------
# UPDATE USER (SUPER ADMIN OR ADMIN)
# -------------------------------------------------------------

@router.patch("/{user_id}", response_model=dict)
def update_user(
    user_id: int,
    req: UserUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Update an existing user account.
    Super Admins can edit any account. Admins can edit standard users or their own account.
    """
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    # Permission check: Only Super Admin can edit Super Admin accounts
    if user.role == "super_admin" and current_user.role != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only Super Administrators can edit Super Administrator accounts.",
        )

    # Role change permission check
    if req.role is not None and req.role != user.role:
        if current_user.role != "super_admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only Super Administrators can change user roles.",
            )
        # Prevent demoting the only super_admin
        if user.role == "super_admin" and req.role != "super_admin":
            super_count = db.scalar(
                select(func.count(User.id)).where(User.role == "super_admin")
            )
            if (super_count or 0) <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot demote the only remaining Super Administrator.",
                )
        user.role = req.role

    # Check username, email, and phone number collisions if changed
    check_username = (
        req.username.strip()
        if req.username is not None and req.username.strip().lower() != user.username.lower()
        else None
    )
    check_email = (
        str(req.email).strip().lower()
        if req.email is not None and str(req.email).strip().lower() != user.email.lower()
        else None
    )
    check_phone = (
        req.phone_number.strip()
        if req.phone_number is not None and req.phone_number.strip() != (user.phone_number or "")
        else None
    )

    if check_username or check_email or check_phone:
        conflicts = check_user_conflicts(
            db=db,
            username=check_username,
            email=check_email,
            phone_number=check_phone,
            exclude_user_id=user_id,
        )
        if not conflicts["available"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=conflicts["detail"],
            )

    if req.username is not None:
        user.username = req.username.strip()
    if req.email is not None:
        user.email = str(req.email).strip().lower()
    if req.phone_number is not None:
        user.phone_number = req.phone_number.strip()

    # Track status changes for audit logging
    previous_is_active = user.is_active
    password_changed = False
    active_changed = False

    # Password
    if req.password is not None and req.password.strip():
        try:
            validate_password_complexity(req.password)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            )
        user.hashed_password = hash_password(req.password)
        user.password_changed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        password_changed = True

    # Active status
    if req.is_active is not None and req.is_active != previous_is_active:
        # Prevent deactivating the only super_admin
        if user.role == "super_admin" and not req.is_active:
            super_active_count = db.scalar(
                select(func.count(User.id)).where(
                    User.role == "super_admin",
                    User.is_active == True,
                )
            )
            if (super_active_count or 0) <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot deactivate the only active Super Administrator.",
                )
        user.is_active = req.is_active
        active_changed = True

    # Verified status
    if req.is_verified is not None:
        user.is_verified = req.is_verified
        if req.is_verified:
            user.activation_token = None

    db.commit()
    db.refresh(user)

    # Log audit events for security operations
    if active_changed:
        action_type = "user_deactivated" if not user.is_active else "user_activated"
        desc = "deactivated" if not user.is_active else "reactivated"
        create_event(
            db=db,
            event_type=action_type,
            message=f"User account '{user.username}' {desc} by {current_user.role} '{current_user.username}'.",
            device_id=None,
            actor=current_user.username,
        )
        db.commit()

    if password_changed:
        create_event(
            db=db,
            event_type="password_reset",
            message=f"Password for user '{user.username}' updated/reset by {current_user.role} '{current_user.username}'.",
            device_id=None,
            actor=current_user.username,
        )
        db.commit()

    if req.password is not None or (req.is_active is not None and req.is_active):
        clear_failed_login_attempts(user.username)
        clear_failed_login_attempts(user.email)

    return {
        "status": "updated",
        "message": f"User '{user.username}' updated successfully.",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "phone_number": user.phone_number,
            "role": user.role,
            "is_active": user.is_active,
            "is_verified": user.is_verified,
        },
    }


# -------------------------------------------------------------
# RESEND ACTIVATION LOGIN LINK
# -------------------------------------------------------------

@router.post("/{user_id}/resend-activation")
def resend_activation_link(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Regenerate and resend the activation login link to the user's email."""
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    token = generate_activation_token()
    login_link = generate_activation_link(token)

    user.activation_token = token
    db.commit()

    send_activation_email(
        email=user.email,
        username=user.username,
        login_link=login_link,
    )

    return {
        "status": "sent",
        "message": f"Activation login link resent to {user.email}.",
        "activation_link": login_link,
    }


# -------------------------------------------------------------
# DELETE USER
# -------------------------------------------------------------

@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Delete a user account."""
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete your own account.",
        )

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    if user.role == "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super Administrator accounts cannot be deleted.",
        )

    db.delete(user)
    db.commit()

    return {
        "status": "deleted",
        "message": f"User '{user.username}' has been deleted.",
    }
