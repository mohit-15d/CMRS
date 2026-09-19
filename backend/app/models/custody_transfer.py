"""CustodyTransfer model - chain-of-custody movement records."""

import uuid

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class CustodyTransfer(Base):
    """One custody hand-off for a piece of evidence.

    - ``previous_custodian_id`` is nullable: the FIRST custody record (the
      original seizure/upload) has no previous custodian.
    - ``authorized_by_id`` records who performed/authorized the transfer.
    - Deleting evidence is RESTRICTed while custody records exist: the
      chain-of-custody history is forensic evidence itself.
    """

    __tablename__ = "custody_transfers"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("evidence.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    previous_custodian_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    new_custodian_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    authorized_by_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )

    action: Mapped[str] = mapped_column(String(50), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    location: Mapped[str | None] = mapped_column(String(255))

    transferred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        server_default=func.now(), index=True,
    )

    # ---- relationships -------------------------------------------------
    evidence: Mapped["Evidence"] = relationship(  # noqa: F821
        back_populates="custody_transfers"
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<CustodyTransfer id={self.id} action={self.action!r}>"
