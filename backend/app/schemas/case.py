"""Case management Pydantic schemas."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Allowed case lifecycle statuses.
CASE_STATUSES = frozenset({"open", "in_progress", "closed"})

CASE_NUMBER_MAX = 50


def _validate_status(value: str) -> str:
    status = value.strip().lower()
    if status not in CASE_STATUSES:
        raise ValueError(
            f"Status must be one of: {', '.join(sorted(CASE_STATUSES))}"
        )
    return status


class CaseBase(BaseModel):
    """Shared case fields (used by create/update responses)."""

    case_number: str
    title: str
    description: str | None = None
    offense: str | None = None
    victim: str | None = None
    suspect: str | None = None
    submitting_officer: str | None = None
    location: str | None = None
    seized_at: datetime | None = None
    status: str = "open"

    @field_validator("case_number")
    @classmethod
    def _case_number(cls, v: str) -> str:
        v = v.strip()
        if not (1 <= len(v) <= CASE_NUMBER_MAX):
            raise ValueError(
                f"Case number must be 1-{CASE_NUMBER_MAX} characters"
            )
        return v

    @field_validator("title")
    @classmethod
    def _title(cls, v: str) -> str:
        v = v.strip()
        if not (1 <= len(v) <= 200):
            raise ValueError("Title must be 1-200 characters")
        return v

    @field_validator("status")
    @classmethod
    def _status(cls, v: str) -> str:
        return _validate_status(v)


class CaseCreate(CaseBase):
    """Payload for creating a case."""


class CaseUpdate(BaseModel):
    """Partial update of a case (all fields optional)."""

    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None)
    description: str | None = Field(default=None)
    offense: str | None = Field(default=None)
    victim: str | None = Field(default=None)
    suspect: str | None = Field(default=None)
    submitting_officer: str | None = Field(default=None)
    location: str | None = Field(default=None)
    seized_at: datetime | None = Field(default=None)
    status: str | None = Field(default=None)
    # Assignment is an administrative capability: grants READ access to the
    # assigned user even for viewer roles (write actions remain role-gated).
    assigned_investigator_id: UUID | None = Field(default=None)

    @field_validator("status")
    @classmethod
    def _status(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return _validate_status(v)

    @field_validator("title")
    @classmethod
    def _title(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not (1 <= len(v) <= 200):
            raise ValueError("Title must be 1-200 characters")
        return v


class CaseRead(CaseBase):
    """Case representation returned to clients (never includes foreign rows)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_by_id: UUID
    assigned_investigator_id: UUID | None = None
    created_at: datetime
    updated_at: datetime


class CaseViewerRead(BaseModel):
    """A viewer a case is shared with (safe fields only: id + username)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    username: str


class ViewerShareRequest(BaseModel):
    """Payload for sharing a case with a viewer (read-only)."""

    model_config = ConfigDict(extra="forbid")

    viewer_id: UUID