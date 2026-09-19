"""User model - CMRS accounts (admin / investigator / viewer)."""

import uuid

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.timestamp import TimestampMixin


class User(TimestampMixin, Base):
    """A CMRS user account.

    Security notes:
    - ``password_hash`` stores ONLY a bcrypt hash; plaintext passwords are
      never stored or returned by the API.
    - ``role`` is a plain string ("admin" | "investigator" | "viewer");
      RBAC enforcement happens in application code.
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(120))
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="viewer")
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )

    # ---- relationships -------------------------------------------------
    cases_created: Mapped[list["Case"]] = relationship(  # noqa: F821
        back_populates="created_by", foreign_keys="Case.created_by_id"
    )
    cases_assigned: Mapped[list["Case"]] = relationship(  # noqa: F821
        back_populates="assigned_investigator",
        foreign_keys="Case.assigned_investigator_id",
    )
    evidence_uploaded: Mapped[list["Evidence"]] = relationship(  # noqa: F821
        back_populates="uploaded_by"
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<User id={self.id} username={self.username!r} role={self.role}>"
