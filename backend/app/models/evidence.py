"""Evidence model - a digital evidence item belonging to a case."""

import uuid

from sqlalchemy import BigInteger, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.timestamp import TimestampMixin


class Evidence(TimestampMixin, Base):
    """A digital evidence item.

    Forensic notes:
    - ``storage_path`` is an INTERNAL storage reference (relative to the
      evidence store). It is never exposed through the API.
    - ``original_filename`` is kept for reporting only; it is never trusted
      for filesystem access (path-traversal protection is applied upstream).
    - Cryptographic hashes live in ``evidence_hashes`` (one-to-many), keeping
      original vs. verification hashes separated.
    - Deleting a case is RESTRICTed while evidence exists; deleting evidence
      removes its hash records (CASCADE) to avoid orphaned rows.
    """

    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    item_number: Mapped[int | None] = mapped_column()  # report "Item Number"
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(127), nullable=False)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="active", index=True
    )

    uploaded_by_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )

    # ---- relationships -------------------------------------------------
    case: Mapped["Case"] = relationship(  # noqa: F821
        back_populates="evidence"
    )
    uploaded_by: Mapped["User"] = relationship(  # noqa: F821
        back_populates="evidence_uploaded"
    )
    hashes: Mapped[list["EvidenceHash"]] = relationship(  # noqa: F821
        back_populates="evidence", cascade="all, delete-orphan"
    )
    custody_transfers: Mapped[list["CustodyTransfer"]] = relationship(  # noqa: F821
        back_populates="evidence"
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Evidence id={self.id} filename={self.original_filename!r}>"
