"""Security alert request and response schemas.

Alerts are advisory only — a human administrator must always review and
resolve or dismiss them.  The system never takes punitive action based
solely on an alert.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.ai_alert import (
    ALERT_SEVERITY_CRITICAL,
    ALERT_SEVERITY_HIGH,
    ALERT_SEVERITY_LOW,
    ALERT_SEVERITY_MEDIUM,
    ALERT_STATUS_DISMISSED,
    ALERT_STATUS_OPEN,
    ALERT_STATUS_REVIEWED,
    ALERT_STATUS_RESOLVED,
)

#: All valid alert statuses, in the recommended workflow order.
_ALERT_STATUS_ORDER = {
    ALERT_STATUS_OPEN: 0,
    ALERT_STATUS_REVIEWED: 1,
    ALERT_STATUS_RESOLVED: 2,
    ALERT_STATUS_DISMISSED: 2,
}


class AlertRead(BaseModel):
    """Public representation of a security alert (admin-facing)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    alert_type: str
    severity: str
    score: Optional[float] = None
    explanation: str
    status: str
    case_id: Optional[UUID] = None
    evidence_id: Optional[UUID] = None
    user_id: Optional[UUID] = None
    reviewed_by_id: Optional[UUID] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    resolution: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class AlertReview(BaseModel):
    """Request to review, resolve, or dismiss an alert.

    ``status`` must be one of ``open``, ``reviewed``, ``resolved``,
    ``dismissed``.  A transition from ``open`` to any non-open status
    records ``reviewed_at`` and ``reviewed_by``; ``resolved`` or
    ``dismissed`` additionally set ``resolved_at``.
    """

    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., max_length=20)
    resolution: Optional[str] = Field(default=None, max_length=2000)

    @field_validator("status")
    @classmethod
    def _validate_status(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in _ALERT_STATUS_ORDER:
            raise ValueError(
                f"Status must be one of: {', '.join(sorted(_ALERT_STATUS_ORDER))}"
            )
        return value

    @field_validator("resolution")
    @classmethod
    def _normalize_resolution(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("Resolution cannot be empty")
        return value


class AlertListParams(BaseModel):
    """Query parameters for filtering alert listings."""

    model_config = ConfigDict(extra="forbid")

    status: Optional[str] = Field(default=None, max_length=20)
    severity: Optional[str] = Field(default=None, max_length=20)
    alert_type: Optional[str] = Field(default=None, max_length=50)
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)

    @field_validator("status")
    @classmethod
    def _validate_status(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = value.strip().lower()
        if value not in _ALERT_STATUS_ORDER:
            raise ValueError(
                f"Status must be one of: {', '.join(sorted(_ALERT_STATUS_ORDER))}"
            )
        return value

    @field_validator("severity")
    @classmethod
    def _validate_severity(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = value.strip().lower()
        allowed = {
            ALERT_SEVERITY_LOW,
            ALERT_SEVERITY_MEDIUM,
            ALERT_SEVERITY_HIGH,
            ALERT_SEVERITY_CRITICAL,
        }
        if value not in allowed:
            raise ValueError(
                f"Severity must be one of: {', '.join(sorted(allowed))}"
            )
        return value
