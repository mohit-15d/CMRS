"""Unit tests for bcrypt password hashing/verification."""

import pytest

from app.security.password import hash_password, verify_password

GOOD = "s3cret-pass!"


class TestPasswordHashing:
    def test_hash_is_not_plaintext(self):
        hashed = hash_password(GOOD)
        assert hashed != GOOD
        assert hashed.startswith("$2")  # bcrypt hash marker

    def test_verify_roundtrip(self):
        hashed = hash_password(GOOD)
        assert verify_password(GOOD, hashed) is True
        assert verify_password("wrong-password", hashed) is False

    def test_unique_salts(self):
        assert hash_password(GOOD) != hash_password(GOOD)

    def test_too_long_hash_raises(self):
        with pytest.raises(ValueError):
            hash_password("x" * 73)

    def test_too_long_verify_returns_false(self):
        hashed = hash_password(GOOD)
        assert verify_password("x" * 73, hashed) is False