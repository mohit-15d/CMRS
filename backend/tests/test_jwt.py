"""Unit tests for JWT create/decode (expiry, tampering, signature)."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt
import pytest

from app.core.config import settings
from app.security.jwt import create_access_token, decode_access_token


class TestJWT:
    def test_roundtrip(self):
        uid = uuid4()
        payload = decode_access_token(create_access_token(uid))
        assert payload["sub"] == str(uid)
        assert payload["type"] == "access"
        assert payload["exp"] > int(datetime.now(timezone.utc).timestamp())

    def test_decode_rejects_garbage(self):
        with pytest.raises(jwt.PyJWTError):
            decode_access_token("not.a.jwt")

    def test_decode_rejects_expired(self):
        now = datetime.now(timezone.utc)
        expired = jwt.encode(
            {
                "sub": str(uuid4()),
                "type": "access",
                "exp": now - timedelta(minutes=5),
            },
            settings.jwt_secret.get_secret_value(),
            algorithm=settings.jwt_algorithm,
        )
        with pytest.raises(jwt.PyJWTError):
            decode_access_token(expired)

    def test_decode_rejects_wrong_signature(self):
        token = create_access_token(uuid4())
        with pytest.raises(jwt.PyJWTError):
            jwt.decode(
                token,
                "x" * 40,  # wrong key >= 32 bytes so no insecure-key warning
                algorithms=[settings.jwt_algorithm],
            )