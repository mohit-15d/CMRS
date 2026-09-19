"""CMRS application configuration.

Loads settings from environment variables (and a local ``.env`` file when
present) using pydantic-settings. No secrets are hard-coded in source code.
"""

from pathlib import Path

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Absolute paths: backend/ directory and the project root above it.
# Used so the env file is located regardless of the current working directory.
BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_DIR.parent

# Candidate env-file locations, in priority order. The first one that exists
# is used. The project chooses to name the config file "backend.env" at the
# project root; all standard alternatives are also supported.
_ENV_CANDIDATES = (
    PROJECT_ROOT / "backend.env",
    BACKEND_DIR / ".env",
    PROJECT_ROOT / ".env",
)
ENV_FILE = next((p for p in _ENV_CANDIDATES if p.exists()), _ENV_CANDIDATES[0])


class Settings(BaseSettings):
    """Application settings loaded from environment variables / .env file."""

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # PostgreSQL connection string, e.g.
    #   postgresql+psycopg://USER:PASSWORD@HOST:PORT/DBNAME
    # Read from the DATABASE_URL environment variable.
    database_url: str = "postgresql+psycopg://cmrs_user:CHANGE_ME@localhost:5432/cmrs_db"

    # JWT authentication. jwt_secret has NO default on purpose: it must be
    # supplied by the environment / backend.env, and a missing secret is a
    # hard startup error. SecretStr keeps it masked in repr()/exported logs.
    jwt_secret: SecretStr
    # Token signature algorithm (HMAC-SHA256 is the standard default).
    jwt_algorithm: str = "HS256"
    # Access-token lifetime in minutes.
    jwt_expire_minutes: int = 60

    # ----- Login rate limiting / lockout -----
    # Per-IP request throttle for the login endpoint.
    login_ratelimit_max: int = 10
    login_ratelimit_window_seconds: int = 60
    # Per-(IP, username) failure lockout.
    login_lockout_max_failures: int = 5
    login_lockout_window_seconds: int = 900

    # ----- Admin bootstrap (first admin user, created on startup) -----
    # Optional: when all four are set AND the username does not exist yet, the
    # app creates an admin at startup. Never logged. Leave unset to skip.
    admin_username: str | None = None
    admin_email: str | None = None
    admin_password: SecretStr | None = None
    admin_full_name: str | None = None

    # Evidence files are stored outside PostgreSQL in a secure filesystem path.
    # Relative paths resolve from the backend directory.
    evidence_storage_dir: str = "../storage/encrypted"

    # Generated chain-of-custody PDF reports (Stage 19). Relative paths
    # resolve from the backend directory.
    reports_storage_dir: str = "../reports"

    # Stage 12: AES-256-GCM encryption key for evidence-at-rest encryption.
    # Must be a 64-character hex string representing 32 bytes (256 bits).
    # No default; must be supplied by environment / backend.env.
    # **KEY MANAGEMENT LIMITATION (Academic/Demo Only):**
    # This loads the key from an environment variable. In production, use:
    # - AWS KMS / Azure Key Vault / Google Cloud KMS
    # - HashiCorp Vault
    # - Hardware Security Module (HSM)
    # Not suitable for production forensic deployments without proper key management.
    encryption_key: SecretStr | None = None

    @field_validator("jwt_expire_minutes")
    @classmethod
    def validate_positive_expiry(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("JWT_EXPIRE_MINUTES must be a positive integer")
        return value

    @field_validator("database_url")
    @classmethod
    def validate_postgres_only(cls, value: str) -> str:
        """Enforce that CMRS uses PostgreSQL and never SQLite or others."""
        stripped = value.strip().lower()
        if not stripped.startswith("postgresql"):
            raise ValueError(
                "CMRS requires PostgreSQL. DATABASE_URL must start with "
                "'postgresql://' or 'postgresql+psycopg://'; "
                f"got '{value[:50]}'."
            )
        return value


settings = Settings()