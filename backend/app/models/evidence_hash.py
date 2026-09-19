"""EvidenceHash model - SHA-256 integrity records for digital evidence."""

import uuid

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class EvidenceHash(Base):
    """A hash record for a piece of evidence.

    ``hash_type`` distinguishes the hash of the ORIGINAL upload bytes
    ("original") from hashes captured during later verifications
    ("verification"). The ORIGINAL record is what integrity checks compare
    against. ``match_result`` records whether a verification matched.
    """

    __tablename__ = "evidence_hashes"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sha256_hex: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    algorithm: Mapped[str] = mapped_column(String(20), nullable=False, default="sha256")
    hash_type: Mapped[str] = mapped_column(String(30), nullable=False, default="original")

    # Verification metadata (filled when the hash was re-checked).
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    match_result: Mapped[bool | None] = mapped_column(Boolean)

    # ---- relationships -------------------------------------------------
    evidence: Mapped["Evidence"] = relationship(  # noqa: F821
        back_populates="hashes"
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<EvidenceHash id={self.id} type={self.hash_type}>"
