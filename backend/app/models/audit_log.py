"""AuditLog model - security-relevant activity records.

Audit rows carry chained hashes so tampering is detectable during verification.
"""

import uuid

from sqlalchemy import JSON, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.timestamp import TimestampMixin


class AuditLog(TimestampMixin, Base):
    """One audited action.

    - ``actor_id`` is nullable: failed logins or system-triggered events may
      not map to a valid user row.
    - ``resource_id`` is a string (not an FK) so any entity type can be
      referenced without polymorphic constraints.
    - ``details`` holds SAFE metadata only (never secrets, passwords or raw
      tokens).
    """

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    action: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    resource_type: Mapped[str | None] = mapped_column(String(50))
    resource_id: Mapped[str | None] = mapped_column(String(64), index=True)
    result: Mapped[str] = mapped_column(String(20), nullable=False, default="success")
    details: Mapped[dict | None] = mapped_column(JSON)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    current_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<AuditLog id={self.id} action={self.action!r} result={self.result!r}>"
