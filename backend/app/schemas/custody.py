"""Chain-of-custody request and response schemas."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

CUSTODY_ACTIONS = {
    "created",
    "received",
    "transferred",
    "examined",
    "returned",
    "stored",
    "final_disposition",
}


class CustodyEventCreate(BaseModel):
    """Payload for appending an evidence custody event."""

    received_by_id: UUID
    action: str = Field(default="transferred", max_length=50)
    comments: str | None = Field(default=None, max_length=5000)
    location: str | None = Field(default=None, max_length=255)

    @field_validator("action")
    @classmethod
    def _validate_action(cls, value: str) -> str:
        value = value.strip().lower().replace(" ", "_")
        if value not in CUSTODY_ACTIONS:
            allowed = ", ".join(sorted(CUSTODY_ACTIONS))
            raise ValueError(f"Action must be one of: {allowed}")
        return value

    @field_validator("comments", "location")
    @classmethod
    def _normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("Text fields cannot be empty")
        return value


class CustodyEventRead(BaseModel):
    """Public immutable custody history entry."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    evidence_id: UUID
    item_number: int | None
    transferred_at: datetime
    released_by: str | None
    released_by_id: UUID | None
    received_by: str
    received_by_id: UUID
    comments: str | None
    location: str | None
    authenticated_user: str
    authenticated_user_id: UUID
    action: str
    status: str
    purpose: str | None


class CustodianOption(BaseModel):
    """Minimal selectable custodian for the custody dropdown.

    Deliberately returns ONLY safe fields (id/username/role) - never email,
    full_name, is_active flags or anything sensitive.
    """

    id: UUID
    username: str
    role: str
