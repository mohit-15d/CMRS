"""Evidence request and response schemas."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IntegrityVerificationRead(BaseModel):
    """Integrity verification result from SHA-256 comparison."""

    model_config = ConfigDict(from_attributes=True)

    evidence_id: UUID
    filename: str
    match: bool
    original_hash: str = Field(description="SHA-256 hash at registration")
    current_hash: str = Field(description="SHA-256 hash at verification")
    algorithm: str
    status: str = Field(description="INTEGRITY VERIFIED or INTEGRITY VIOLATION")
    verified_at: datetime
    verified_by: str
    verified_by_id: UUID


class EvidenceCreate(BaseModel):
    """Upload payload for a new evidence record."""

    case_id: UUID
    item_number: int | None = Field(default=None, ge=1)
    description: str | None = Field(default=None, max_length=5000)

    @field_validator("description")
    @classmethod
    def _normalize_description(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("Description cannot be empty")
        return value


class EvidenceRead(BaseModel):
    """Evidence metadata returned via the API."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    case_id: UUID
    item_number: int | None = None
    original_filename: str
    storage_path: str
    mime_type: str
    file_size: int
    description: str | None = None
    status: str
    uploaded_by_id: UUID
    created_at: datetime
    updated_at: datetime


class EvidenceHashRead(BaseModel):
    """One recorded SHA-256 hash (original or verification) for evidence."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    sha256_hex: str
    algorithm: str
    hash_type: str
    match_result: bool | None = None
    verified_at: datetime | None = None


class EvidenceDetailRead(EvidenceRead):
    """Evidence metadata plus integrity hash records."""

    original_hash: EvidenceHashRead | None = None
    latest_verification: EvidenceHashRead | None = None
    # Username of the uploader, resolved server-side from the ORM
    # relationship (the raw uploaded_by_id UUID stays available above).
    uploaded_by: str | None = None

    @field_validator("uploaded_by", mode="before")
    @classmethod
    def _uploaded_by_username(cls, value: object) -> str | None:
        """Coerce the ORM ``uploaded_by`` User relationship to a username."""
        if value is not None and not isinstance(value, str):
            return getattr(value, "username", None)
        return value if isinstance(value, str) else None
