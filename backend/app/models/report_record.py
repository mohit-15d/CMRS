"""ReportRecord model - generated chain-of-custody PDF report records."""

import uuid

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.timestamp import TimestampMixin


class ReportRecord(TimestampMixin, Base):
    """Metadata about a generated PDF chain-of-custody report.

    ``storage_reference`` points to the PDF on disk (internal; never exposed
    as a raw filesystem path through the API - downloads stream through a
    controlled endpoint).
    """

    __tablename__ = "report_records"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    report_identifier: Mapped[str] = mapped_column(
        String(100), unique=True, nullable=False
    )
    generated_by_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    storage_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="generated")

    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<ReportRecord id={self.id} case={self.case_id}>"
