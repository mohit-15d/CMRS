"""Admin bootstrap tests (function-level; lifespan not triggered in tests)."""

from pydantic import EmailStr, SecretStr, TypeAdapter

from app.core.bootstrap import ensure_bootstrap_admin
from app.core.config import settings
from app.core.roles import ADMIN
from app.models.user import User
from app.security.password import verify_password


def _configure_admin(monkeypatch, *, username="bootadmin", password="Boot-Admin-1"):
    monkeypatch.setattr(settings, "admin_username", username)
    monkeypatch.setattr(settings, "admin_email", f"{username}@example.com")
    monkeypatch.setattr(settings, "admin_password", SecretStr(password))
    monkeypatch.setattr(settings, "admin_full_name", "Bootstrap Admin")


def test_creates_admin_when_absent(db_session, monkeypatch):
    _configure_admin(monkeypatch)
    assert ensure_bootstrap_admin(db_session) is True


def test_admin_has_correct_role_and_verifiable_password(db_session, monkeypatch):
    _configure_admin(monkeypatch, password="secret-Admin-1")
    ensure_bootstrap_admin(db_session)
    admin = db_session.query(User).filter_by(username="bootadmin").first()
    assert admin is not None
    assert admin.role == ADMIN
    assert admin.is_active is True
    assert verify_password("secret-Admin-1", admin.password_hash) is True


def test_idempotent(db_session, monkeypatch):
    _configure_admin(monkeypatch)
    assert ensure_bootstrap_admin(db_session) is True
    assert ensure_bootstrap_admin(db_session) is False
    assert db_session.query(User).filter_by(username="bootadmin").count() == 1


def test_noop_when_unset(db_session, monkeypatch):
    monkeypatch.setattr(settings, "admin_username", None)
    assert ensure_bootstrap_admin(db_session) is False


def test_configured_admin_email_is_a_valid_emailstr():
    """Guard against a bootstrap admin email that breaks EmailStr.

    A value like ``admin@example.local`` is a special-use/reserved domain that
    email-validator rejects, which previously surfaced as a 500 when
    serializing the admin through UserPublic (whose email field is
    ``EmailStr``). The configured bootstrap email must always validate.
    """
    assert settings.admin_email is not None
    validated = TypeAdapter(EmailStr).validate_python(settings.admin_email)
    assert validated.lower() == settings.admin_email.lower()