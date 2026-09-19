"""CMRS - temporary PostgreSQL connectivity check.

This is a TEMPORARY diagnostic script, NOT part of the application API.
It proves whether CMRS can reach PostgreSQL using the configured
DATABASE_URL (from env / .env via app.core.config).

Run from the backend/ directory:

    .venv\\Scripts\\python scripts\\check_db_connection.py

Exit codes: 0 = connection SUCCESS, 1 = connection FAILURE.
The database password is never printed (DSN is redacted).
"""

import sys
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import text

from app.core.config import settings
from app.db.session import engine


def redact_dsn(dsn: str) -> str:
    """Return the DSN with the password portion replaced by '***'."""
    try:
        parts = urlsplit(dsn)
        if parts.password:
            hostname = parts.hostname or ""
            netloc = f"{parts.username}:***@{hostname}"
            if parts.port:
                netloc += f":{parts.port}"
            dsn = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    except Exception:  # noqa: BLE001 - never fail redaction
        dsn = "(unable to parse DSN)"
    return dsn


def main() -> int:
    print("CMRS PostgreSQL connectivity check")
    print(f"Target        : {redact_dsn(settings.database_url)}")

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 - report the failure clearly
        print("")
        print("DB_CONNECT: FAILURE")
        print(f"Error       : {exc}")
        print("Hint        : Check that PostgreSQL is running and that DATABASE_URL in .env is correct.")
        return 1

    print("")
    print("DB_CONNECT: SUCCESS")
    return 0


if __name__ == "__main__":
    sys.exit(main())