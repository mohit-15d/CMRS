"""Admin bootstrap - create the first admin user from environment settings.

Security contract:
- Only runs when ALL of ``admin_username``, ``admin_email``, and
  ``admin_password`` are configured. Partial configuration is treated as "not
  configured" (fail-safe: no admin is created).
- Idempotent: if a user with that username already exists, nothing happens.
- Passwords are hashed with bcrypt, never logged.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.roles import ADMIN
from app.models.user import User
from app.security.password import hash_password


def ensure_bootstrap_admin(db: Session) -> bool:
    """Create the bootstrap admin if configured and absent.

    Returns True if an admin was created, False otherwise (no-op / not set).
    """
    username = settings.admin_username
    email = settings.admin_email
    password = settings.admin_password
    if not (username and email and password):
        return False

    if db.execute(select(User).where(User.username == username)).scalar_one_or_none():
        return False

    admin = User(
        username=username,
        email=email,
        password_hash=hash_password(password.get_secret_value()),
        full_name=settings.admin_full_name,
        role=ADMIN,
        is_active=True,
    )
    db.add(admin)
    db.commit()
    return True