"""JWT access-token creation and validation.

The signing secret comes exclusively from ``settings.jwt_secret`` (loaded from
the environment / ``backend.env``). Nothing here hard-codes a secret, and
secrets are never printed or logged.

Every access token carries a unique ``jti`` (JWT ID) claim. The ``jti`` is
used for stateless logout: a token can be revoked by its id while an unexpired
token remains valid. (Revocation is a deny-list performed by ``token_store``.)
"""

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import jwt

from app.core.config import settings


def create_access_token(user_id: UUID) -> str:
    """Create a signed JWT access token for the given user id.

    Claims: ``sub`` = user id, ``type`` = "access", ``jti`` = unique token id,
    ``iat`` and ``exp`` set to UTC datetimes. Expiry is
    ``settings.jwt_expire_minutes`` minutes.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "type": "access",
        "jti": str(uuid4()),
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_expire_minutes),
    }
    return jwt.encode(
        payload,
        settings.jwt_secret.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )


def decode_access_token(token: str) -> dict:
    """Decode and validate an access token.

    Returns the decoded payload (which includes ``sub``, ``jti``, ``exp``).

    Raises:
        jwt.PyJWTError: for any invalid, tampered, or expired token. Callers
            (e.g. the current-user dependency) map this to a 401 response.
    """
    payload = jwt.decode(
        token,
        settings.jwt_secret.get_secret_value(),
        algorithms=[settings.jwt_algorithm],
    )
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("token is not an access token")
    if not payload.get("jti"):
        raise jwt.InvalidTokenError("token is missing its jti claim")
    return payload