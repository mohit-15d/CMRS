"""FastAPI dependencies shared across routers.

- ``get_current_user`` authenticates the caller from a Bearer access token and
  resolves it to a ``User`` row, or fails with ``401``. It also rejects tokens
  that have been revoked on logout (deny-list by ``jti``).
- ``require_roles``/``require_admin`` layer RBAC on top of authentication:
  a caller whose role is not in the allowed set gets ``403 Forbidden``.
"""

import uuid
from collections.abc import Callable

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.roles import ADMIN
from app.db.session import get_db
from app.models.user import User
from app.security.jwt import decode_access_token
from app.security.token_store import token_store

_bearer = HTTPBearer(auto_error=False)


def _unauthorized(detail: str = "Invalid or expired token") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _forbidden() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Insufficient permissions",
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    """Resolve and return the authenticated user (401 on any failure)."""
    if credentials is None:
        raise _unauthorized("Not authenticated")

    try:
        payload = decode_access_token(credentials.credentials)
        user_id = uuid.UUID(str(payload.get("sub")))
        jti = str(payload.get("jti"))
    except (jwt.PyJWTError, ValueError, TypeError):
        raise _unauthorized()

    if token_store.is_revoked(jti):
        raise _unauthorized("Token has been revoked")

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise _unauthorized()

    return user


def require_roles(*allowed: str) -> Callable[..., User]:
    """Return a dependency that allows only users whose role is in ``allowed``.

    Use as ``Depends(require_roles(ADMIN, INVESTIGATOR))``. Returns the user
    when permitted, else raises 403. Always requires a valid token first.
    """

    def dependency(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role not in allowed:
            raise _forbidden()
        return current_user

    return dependency


#: Convenience dependency for admin-only routes.
require_admin = require_roles(ADMIN)