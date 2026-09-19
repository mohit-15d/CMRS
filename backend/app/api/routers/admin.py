"""Admin - user management routes (RBAC: ADMIN only).

Every route requires the ``admin`` role via ``require_admin``. Non-admin
authenticated users (investigator/viewer) get 403; unauthenticated callers get
401.

Security:
- ``POST``/``PATCH``/password-reset are admin-only.
- The bootstrap/last active admin cannot be demoted or deactivated, preventing
  accidental total lockout of the system.
- Duplicate username/email is surfaced as 409 (not a 500).
- User public serialization never includes ``password_hash``.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.core.roles import ADMIN
from app.db.session import get_db
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.admin import AdminPasswordReset, UserCreateAdmin, UserUpdate
from app.schemas.audit import AuditLogRead
from app.schemas.auth import UserPublic
from app.security.password import hash_password
from app.security.audit_ledger import append_audit_event

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _get_user_or_404(db: Session, user_id: uuid.UUID) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    return user


@router.get("/users", response_model=list[UserPublic])
def list_users(
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> list[User]:
    """Return all users (admin-only)."""
    return list(db.execute(select(User).order_by(User.created_at)).scalars())


@router.post(
    "/users",
    response_model=UserPublic,
    status_code=status.HTTP_201_CREATED,
)
def create_user(
    payload: UserCreateAdmin,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> User:
    """Create a user with an admin-controlled role."""
    existing = db.execute(
        select(User).where(
            or_(User.username == payload.username, User.email == payload.email)
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email is already registered",
        )

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        full_name=payload.full_name,
        role=payload.role,
        is_active=True,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email is already registered",
        )
    db.refresh(user)
    return user


@router.patch("/users/{user_id}", response_model=UserPublic)
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> User:
    """Update a user's role / active status / full name (admin-only)."""
    try:
        payload.require_any_change()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        )

    user = _get_user_or_404(db, user_id)
    previous_role = user.role
    previous_active = user.is_active

    if user is admin_user and payload.is_active is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot deactivate your own account",
        )

    # Last-active-admin guard: never allow removing the system's only active
    # admin (prevents accidental total lockout).
    if _is_last_admin(db, user) and (
        payload.is_active is False or (payload.role is not None and payload.role != ADMIN)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot demote or deactivate the last active admin",
        )

    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
    if payload.full_name is not None:
        user.full_name = payload.full_name

    if payload.role is not None and payload.role != previous_role:
        append_audit_event(
            db,
            actor_id=admin_user.id,
            action="USER_ROLE_CHANGED",
            resource_type="user",
            resource_id=str(user.id),
            details={"previous_role": previous_role, "new_role": user.role},
        )
    if previous_active and payload.is_active is False:
        append_audit_event(
            db,
            actor_id=admin_user.id,
            action="USER_DISABLED",
            resource_type="user",
            resource_id=str(user.id),
            details={"previous_active": True, "new_active": False},
        )

    db.commit()
    db.refresh(user)
    return user


@router.post("/users/{user_id}/reset-password", status_code=status.HTTP_204_NO_CONTENT)
def reset_password(
    user_id: uuid.UUID,
    payload: AdminPasswordReset,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> None:
    """Administratively reset a user's password."""
    user = _get_user_or_404(db, user_id)
    user.password_hash = hash_password(payload.new_password)
    db.commit()
    return None


def _is_last_admin(db: Session, user: User) -> bool:
    """True if ``user`` is the only ACTIVE admin in the system."""
    if user.role != ADMIN or not user.is_active:
        return False
    active_admins = db.execute(
        select(User).where(User.role == ADMIN, User.is_active.is_(True))
    ).scalars().all()
    return len(active_admins) == 1


@router.get("/audit-logs", response_model=list[AuditLogRead])
def list_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    action: str | None = Query(default=None, max_length=50),
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> list[AuditLogRead]:
    """Return the most recent audit events (admin-only, newest first)."""
    query = db.query(AuditLog, User.username).outerjoin(
        User, AuditLog.actor_id == User.id
    )
    if action:
        query = query.filter(AuditLog.action == action.upper())
    rows = (
        query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(limit)
        .all()
    )
    return [
        AuditLogRead(
            id=log.id,
            created_at=log.created_at,
            actor_id=log.actor_id,
            actor_username=username,
            action=log.action,
            resource_type=log.resource_type,
            resource_id=log.resource_id,
            result=log.result,
            details=log.details,
        )
        for log, username in rows
    ]