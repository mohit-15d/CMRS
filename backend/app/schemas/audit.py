"""Audit ledger response schemas."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class AuditLogRead(BaseModel):
    """One audited action as returned by the admin audit-log listing."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime
    actor_id: UUID | None = None
    actor_username: str | None = None
    action: str
    resource_type: str | None = None
    resource_id: str | None = None
    result: str
    details: dict | None = None


class AuditLedgerVerificationRead(BaseModel):
    """Result of verifying the complete tamper-evident audit chain."""

    valid: bool
    status: str = Field(description="AUDIT CHAIN VALID or AUDIT CHAIN INVALID")
    checked_records: int
    error: str | None = None
