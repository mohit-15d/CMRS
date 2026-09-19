"""Authentication routes: register, login, logout, and current-user.

Scope (Phase 7): authentication + RBAC foundations.
- Roles are stored on users; ``/api/admin`` enforces admin (RBAC example).
- Login is rate-limited (per-IP throttle + per-username lockout).
- Logout revokes the current access token (JWT deny-list).
- Registration always assigns ``viewer`` role - a client-supplied ``role``
  field on the payload is ignored (no privilege self-escalation).

Stage 18: an excessive-failed-logins security alert is raised when the
per-(IP, username) lockout triggers. Alerts are advisory only - they never
accuse or punish the account holder.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import jwt

from app.api.deps import _bearer, get_current_user
from app.core.config import settings
from app.core.roles import VIEWER
from app.db.session import get_db
from app.models.ai_alert import ALERT_TYPE_EXCESSIVE_FAILED_LOGINS
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    TokenResponse,
    UserCreate,
    UserPublic,
)
from app.security.jwt import create_access_token, decode_access_token
from app.security.password import hash_password, verify_password
from app.security.rate_limit import rate_limiter
from app.security.token_store import token_store
from app.security.audit_ledger import append_audit_event
from app.services.alerts import create_alert

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=UserPublic,
    status_code=status.HTTP_201_CREATED,
)
def register(payload: UserCreate, db: Session = Depends(get_db)) -> User:
    """Create a user account with the ``viewer`` role. No hash ever returned."""
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
        role=VIEWER,  # Never a client-supplied role.
        is_active=True,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        # Concurrent registration with the same username/email.
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email is already registered",
        )
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticate and return a JWT access token (rate-limited)."""
    client_ip = request.client.host if request.client else "unknown"

    # Per-IP request throttle - applies before any credential work.
    if not rate_limiter.hit(
        f"login_ip:{client_ip}",
        settings.login_ratelimit_window_seconds,
        settings.login_ratelimit_max,
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later.",
        )

    # Per-(IP, username) lockout after repeated failures.
    lockout_key = f"login_fail:{client_ip}:{payload.username}"
    if not rate_limiter.hit(
        lockout_key,
        settings.login_lockout_window_seconds,
        settings.login_lockout_max_failures,
    ):
        # Stage 18: raise an advisory security alert for the account lockout.
        # The alert is informational - it does not accuse the account holder.
        locked_user = db.execute(
            select(User).where(User.username == payload.username)
        ).scalar_one_or_none()
        create_alert(
            db,
            alert_type=ALERT_TYPE_EXCESSIVE_FAILED_LOGINS,
            severity="high",
            user_id=locked_user.id if locked_user else None,
            actor_id=locked_user.id if locked_user else None,
            explanation=(
                "Excessive failed login attempts for username "
                f"'{payload.username}' from IP {client_ip} triggered an "
                "account lockout. Advisory only; the account holder may "
                "be unaware and is not accused."
            ),
            details={
                "username": payload.username,
                "client_ip": client_ip,
                "lockout_window_seconds": settings.login_lockout_window_seconds,
            },
            dedupe={
                "alert_type": ALERT_TYPE_EXCESSIVE_FAILED_LOGINS,
                "user_id": locked_user.id if locked_user else None,
            },
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again later.",
        )
    user = db.execute(
        select(User).where(User.username == payload.username)
    ).scalar_one_or_none()

    # Identical message for unknown user and wrong password so the API does
    # not reveal which usernames exist.
    if user is None or not verify_password(payload.password, user.password_hash):
        append_audit_event(
            db,
            actor_id=user.id if user is not None else None,
            action="LOGIN_FAILURE",
            resource_type="user",
            resource_id=str(user.id) if user is not None else None,
            result="failure",
            details={"reason": "Invalid credentials"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    if not user.is_active:
        append_audit_event(
            db,
            actor_id=user.id,
            action="LOGIN_FAILURE",
            resource_type="user",
            resource_id=str(user.id),
            result="failure",
            details={"reason": "Inactive account"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive",
        )

    # A successful login resets this username's failure counter for this IP.
    rate_limiter.clear(lockout_key)

    append_audit_event(
        db,
        actor_id=user.id,
        action="LOGIN",
        resource_type="user",
        resource_id=str(user.id),
    )
    db.commit()

    return TokenResponse(
        access_token=create_access_token(user.id),
        token_type="bearer",
        expires_in=settings.jwt_expire_minutes * 60,
    )


@router.get("/me", response_model=UserPublic)
def me(current_user: User = Depends(get_current_user)) -> User:
    """Return the authenticated user's public profile."""
    return current_user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> None:
    """Revoke the presented access token (JWT deny-list).

    The client should discard the token after this call. Because revocation is
    a deny-list by ``jti``, this prevents the (still unexpired) token from
    being accepted afterwards. Missing or malformed credentials are treated as
    ``401``.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_access_token(credentials.credentials)
        jti = str(payload["jti"])
        exp = float(payload["exp"])
    except (jwt.PyJWTError, KeyError, ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_store.revoke(jti, exp)
    try:
        user_id = uuid.UUID(str(payload.get("sub")))
    except (ValueError, TypeError):
        user_id = None
    append_audit_event(
        db,
        actor_id=user_id,
        action="LOGOUT",
        resource_type="user",
        resource_id=str(user_id) if user_id else None,
    )
    db.commit()
    return None
