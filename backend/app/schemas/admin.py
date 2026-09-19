"""Admin user-management schemas.

Created by an ADMIN only. ``role`` here is an admin-controlled field (unlike
self-registration which always assigns ``viewer``); validation enforces that
the role is one of the known CMRS roles.
"""

from re import compile

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.roles import ADMIN, INVESTIGATOR, VIEWER
from app.security.password import BCRYPT_MAX_BYTES

ALLOWED_ROLES = frozenset({ADMIN, INVESTIGATOR, VIEWER})

_USERNAME_RE = compile(r"^[A-Za-z0-9_.-]+$")


def _validate_username(value: str) -> str:
    value = value.strip()
    if not (3 <= len(value) <= 50):
        raise ValueError("Username must be 3-50 characters")
    if not _USERNAME_RE.fullmatch(value):
        raise ValueError("Username may only contain letters, digits, '_', '.' and '-'")
    return value


def _validate_role(value: str) -> str:
    role = value.strip().lower()
    if role not in ALLOWED_ROLES:
        raise ValueError(f"Role must be one of: {', '.join(sorted(ALLOWED_ROLES))}")
    return role


def _validate_password(value: str) -> str:
    if not (8 <= len(value) <= 64):
        raise ValueError("Password must be 8-64 characters")
    if len(value.encode("utf-8")) > BCRYPT_MAX_BYTES:
        raise ValueError("Password exceeds the 72-byte bcrypt limit")
    return value


class UserCreateAdmin(BaseModel):
    """Create a user as an admin - MAY specify the role."""

    username: str
    email: str
    password: str
    role: str = VIEWER
    full_name: str | None = None

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        return _validate_username(v)

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        if "@" not in v or len(v) > 255:
            raise ValueError("A valid email is required")
        return v

    @field_validator("role")
    @classmethod
    def _role(cls, v: str) -> str:
        return _validate_role(v)

    @field_validator("password")
    @classmethod
    def _password(cls, v: str) -> str:
        return _validate_password(v)


class UserUpdate(BaseModel):
    """Partial update of a user (all fields optional)."""

    model_config = ConfigDict(extra="forbid")

    role: str | None = Field(default=None)
    is_active: bool | None = Field(default=None)
    full_name: str | None = Field(default=None)

    @field_validator("role")
    @classmethod
    def _role(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return _validate_role(v)

    def require_any_change(self) -> None:
        """True if at least one field was provided - call before applying."""
        if self.role is None and self.is_active is None and self.full_name is None:
            raise ValueError("At least one field must be provided")


class AdminPasswordReset(BaseModel):
    """Administrative password reset."""

    new_password: str

    @field_validator("new_password")
    @classmethod
    def _new_password(cls, v: str) -> str:
        return _validate_password(v)