"""Password hashing and verification using bcrypt.

bcrypt is used directly (not passlib) because passlib 1.7.4 is incompatible
with bcrypt>=4.1 (the installed bcrypt is 5.0.0). BCrypt caps input at 72
bytes; a longer plaintext raises ``ValueError``, which we surface on hashing
and convert to a plain failure on verification (callers must never learn the
reason via an exception path).
"""

import bcrypt

#: Maximum byte length bcrypt will hash. Longer plaintexts must be rejected.
BCRYPT_MAX_BYTES = 72


def hash_password(password: str) -> str:
    """Hash a plaintext password with bcrypt.

    Raises:
        ValueError: if the UTF-8 encoding of ``password`` exceeds bcrypt's
            72-byte limit.
    """
    plain = password.encode("utf-8")
    if len(plain) > BCRYPT_MAX_BYTES:
        raise ValueError("Password exceeds the 72-byte bcrypt limit")
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain, salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash.

    Never raises for a too-long/invalid input: any bcrypt ``ValueError`` is
    treated as a verification failure, so callers see only ``False``.
    """
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False