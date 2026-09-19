"""SystemLog model - application/system-level event logging."""

import uuid

from sqlalchemy import JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.timestamp import TimestampMixin


class SystemLog(TimestampMixin, Base):
    """A system-level log entry (startup, errors, security events).

    ``details`` must contain SAFE metadata only - never secrets.
    """

    __tablename__ = "system_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    event_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict | None] = mapped_column(JSON)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<SystemLog id={self.id} type={self.event_type!r} sev={self.severity}>"
