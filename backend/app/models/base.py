"""SQLAlchemy declarative base shared by every CMRS model.

All models MUST inherit from :class:`Base` so that they are registered in a
single ``MetaData`` object. This lets Alembic discover every table during
autogeneration (Phase 5) and keeps constraint naming consistent.

CMRS uses SQLAlchemy 2.x declarative style (``DeclarativeBase`` +
``Mapped``/``mapped_column``).
"""

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

# Explicit constraint/index naming convention. Deterministic names matter for
# Alembic migrations: unnamed constraints would otherwise get random names,
# making later diffs unstable.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base for all CMRS ORM models."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)
