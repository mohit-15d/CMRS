"""Authentication request/response schemas.

Security contract: ``UserPublic`` deliberately has NO ``password_hash`` field,
so password hashes can never be serialized into an API response.
"""

from datetime import datetime
from re import Pattern, compile
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, field_validator

from app.security.password import BCRYPT_MAX_BYTES

_USERNAME_RE: Pattern[str] = compile(r"^[A-Za-z0-9_.-]+$")


class UserCreate(BaseModel):
    """Registration payload."""

    username: str
    email: EmailStr
    password: str
    full_name: str | None = None

    @field_validator("username")
    @classmethod
    def _validate_username(cls, value: str) -> str:
        value = value.strip()
        if not (3 <= len(value) <= 50):
            raise ValueError("Username must be 3-50 characters")
        if not _USERNAME_RE.fullmatch(value):
            raise ValueError("Username may only contain letters, digits, '_', '.' and '-'")
        return value

    @field_validator("password")
    @classmethod
    def _validate_password(cls, value: str) -> str:
        if not (8 <= len(value) <= 64):
            raise ValueError("Password must be 8-64 characters")
        if len(value.encode("utf-8")) > BCRYPT_MAX_BYTES:
            raise ValueError("Password exceeds the 72-byte bcrypt limit")
        return value


class UserPublic(BaseModel):
    """Public user representation - NEVER includes password_hash."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    username: str
    email: EmailStr
    full_name: str | None = None
    role: str
    is_active: bool
    created_at: datetime


class LoginRequest(BaseModel):
    """Login payload (JSON)."""

    username: str
    password: str


class TokenResponse(BaseModel):
    """Successful login response containing a JWT access token."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int