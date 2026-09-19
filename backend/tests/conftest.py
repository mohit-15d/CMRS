"""Shared pytest fixtures.

Because the development DB role cannot create databases (verified:
``cmrs_user`` has ``rolcreatedb=False``), tests run against the configured
``cmrs_db`` but inside one outer transaction per test that is always ROLLED
BACK at teardown. No user rows ever persist to the development database.

The TestClient is deliberately NOT used as a context manager so that the FastAPI
lifespan (which would create the on-disk bootstrap admin against the real
database) does not run during tests; the app's requests share the same
SAVEPOINT transaction as the test session.
"""

import os
import secrets
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from pathlib import Path
from dotenv import load_dotenv

# Load backend.env before any imports that depend on settings
_BACKEND_DIR = Path(__file__).resolve().parents[1]
_PROJECT_ROOT = _BACKEND_DIR.parent
_ENV_FILE = _PROJECT_ROOT / "backend.env"
if _ENV_FILE.exists():
    load_dotenv(_ENV_FILE)

# Tests always use an ephemeral key, never a configured or committed secret.
os.environ["ENCRYPTION_KEY"] = secrets.token_hex(32)

from app.core.config import settings
from app.db.session import get_db
from app.main import app
from app.models.user import User
from app.security.password import hash_password
from app.security.rate_limit import rate_limiter
from app.security.token_store import token_store


@pytest.fixture(autouse=True)
def _isolate_encryption_key(monkeypatch):
    """Give each test an ephemeral key and restore the process environment."""
    monkeypatch.setenv("ENCRYPTION_KEY", secrets.token_hex(32))
    yield


@pytest.fixture()
def db_session():
    """A single shared SQLAlchemy session on an uncommitted outer transaction."""
    engine = create_engine(settings.database_url, pool_pre_ping=True)
    connection = engine.connect()
    outer = connection.begin()
    factory = sessionmaker(bind=connection, join_transaction_mode="create_savepoint")
    session = factory()
    try:
        yield session
    finally:
        session.close()
        outer.rollback()
        connection.close()
        engine.dispose()


@pytest.fixture()
def client(db_session):
    """A TestClient whose DB sessions share the rolled-back transaction.

    The TestClient is not entered as a context manager, so the FastAPI
    lifespan does not run (it would alter the real database).
    """
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    c = TestClient(app)
    try:
        yield c
    finally:
        app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def _reset_security_state():
    """Reset the in-memory rate limiter and token-revocation store between tests.

    The TestClient always presents the same host IP, so without this reset
    login attempts would leak across tests and break rate-limit assertions.
    """
    rate_limiter.reset()
    token_store.reset()
    yield


def create_user(
    db_session,
    *,
    role: str = "viewer",
    username: str | None = None,
    email: str | None = None,
    password: str = "Passw0rd!x",
    full_name: str | None = None,
) -> User:
    """Insert a user into the rolled-back session and return the ORM object."""
    username = username or f"user_{uuid.uuid4().hex[:10]}"
    email = email or f"{username}@example.com"
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        full_name=full_name,
        role=role,
        is_active=True,
    )
    db_session.add(user)
    db_session.flush()
    return user


@pytest.fixture()
def user_factory(db_session):
    def _make(**kwargs) -> User:
        return create_user(db_session, **kwargs)

    return _make


@pytest.fixture()
def login_headers(client):
    """Return a helper that logs in and returns Bearer auth headers."""

    def _login(username: str, password: str) -> dict:
        resp = client.post(
            "/api/auth/login",
            json={"username": username, "password": password},
        )
        assert resp.status_code == 200, resp.text
        return {"Authorization": f"Bearer {resp.json()['access_token']}"}

    return _login