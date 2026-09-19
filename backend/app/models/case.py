"""Case model - an investigation case that groups digital evidence."""

import uuid

from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, String, Table, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column, relationship

from app.models.base import Base
from app.models.timestamp import TimestampMixin

#: Investigator -> Viewer case sharing (many-to-many).
#: Purely additive: ``created_by_id`` / ``assigned_investigator_id`` remain the
#: ownership/assignment source of truth and are NEVER modified by sharing.
#: Rows here grant the listed user READ-ONLY access to the case only.
case_viewers = Table(
    "case_viewers",
    Base.metadata,
    Column(
        "case_id",
        ForeignKey("cases.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    ),
    Column(
        "user_id",
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    ),
)


class Case(TimestampMixin, Base):
    """An investigation case.

    ``created_by_id`` is required (someone must always create a case).
    ``assigned_investigator_id`` is optional until an investigator is
    assigned. Deleting a user who created cases is RESTRICTed to preserve
    accountability records.

    Forensic case fields (offense, victim, suspect, submitting officer,
    location, seized date/time) support the chain-of-custody reporting format.
    """

    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    case_number: Mapped[str] = mapped_column(
        String(50), unique=True, index=True, nullable=False
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    # ----- forensic case details (reportable fields) -----
    offense: Mapped[str | None] = mapped_column(String(200))
    victim: Mapped[str | None] = mapped_column(String(200))
    suspect: Mapped[str | None] = mapped_column(String(200))
    submitting_officer: Mapped[str | None] = mapped_column(String(200))
    location: Mapped[str | None] = mapped_column(String(255))
    seized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="open", index=True
    )

    created_by_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    assigned_investigator_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )

    # ---- relationships -------------------------------------------------
    created_by: Mapped["User"] = relationship(  # noqa: F821
        back_populates="cases_created", foreign_keys=[created_by_id]
    )
    assigned_investigator: Mapped["User | None"] = relationship(  # noqa: F821
        back_populates="cases_assigned", foreign_keys=[assigned_investigator_id]
    )
    evidence: Mapped[list["Evidence"]] = relationship(  # noqa: F821
        back_populates="case"
    )
    #: Viewers this case was explicitly shared with (read-only access).
    viewers: Mapped[list["User"]] = relationship(  # noqa: F821
        "User", secondary=case_viewers
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Case id={self.id} case_number={self.case_number!r}>"


def is_shared_with(db: Session, case: "Case", user_id: uuid.UUID) -> bool:
    """True when an explicit ``case_viewers`` row grants ``user_id`` read access.

    Single server-side membership check reused by every case-read gate
    (cases / evidence / custody history / report download) so the shared-viewer
    grant cannot drift between routers.
    """
    stmt = (
        select(case_viewers.c.case_id)
        .where(
            case_viewers.c.case_id == case.id,
            case_viewers.c.user_id == user_id,
        )
        .limit(1)
    )
    return db.execute(stmt).first() is not None
