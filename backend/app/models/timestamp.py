"""Shared timestamp columns (UTC) mixed into CMRS models."""

from datetime import datetime

from sqlalchemy import DateTime, func
from sqlalchemy.orm import Mapped, mapped_column


class TimestampMixin:
    """Adds created_at / updated_at (timezone-aware, server-generated).

    PostgreSQL ``timestamptz`` stores values in UTC; ``func.now()`` is
    evaluated inside the database so clock consistency is centralized there.
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        sort_order=-900,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
        sort_order=-899,
    )
