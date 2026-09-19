"""SQLAlchemy engine, session factory, and FastAPI dependency.

CMRS uses PostgreSQL ONLY. The engine is created lazily from the settings in
app.core.config. Models and tables are not defined yet (added in later phases).
"""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,  # detects dead connections
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: yield a database session and safely close it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()