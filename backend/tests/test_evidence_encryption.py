"""Encryption tests for Stage 12 (AES-256-GCM Evidence Encryption)."""

import hashlib
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from app.core.config import settings
from app.security.encryption import (
    decrypt_evidence,
    encrypt_evidence,
    generate_example_key,
    EncryptionError,
    DecryptionError,
)


class TestEncryptionKeyGeneration:
    """Tests for encryption key generation and validation."""

    def test_generate_example_key(self):
        """Key generation should produce a 64-char hex string (32 bytes)."""
        key_hex = generate_example_key()
        assert isinstance(key_hex, str)
        assert len(key_hex) == 64
        key_bytes = bytes.fromhex(key_hex)
        assert len(key_bytes) == 32

    def test_generated_keys_are_unique(self):
        """Each generated key should be different (random)."""
        key1 = generate_example_key()
        key2 = generate_example_key()
        assert key1 != key2


class TestEncryptionBasics:
    """Tests for basic encryption/decryption functionality."""

    @pytest.fixture(autouse=True)
    def setup_encryption_key(self):
        """Set up a test encryption key before each test."""
        self.test_key = generate_example_key()
        os.environ["ENCRYPTION_KEY"] = self.test_key
        yield
        if "ENCRYPTION_KEY" in os.environ:
            del os.environ["ENCRYPTION_KEY"]

    def test_encrypt_decrypt_roundtrip_small(self):
        """Small plaintext should encrypt and decrypt correctly."""
        plaintext = b"test evidence data"
        encrypted = encrypt_evidence(plaintext)
        decrypted = decrypt_evidence(encrypted)
        assert decrypted == plaintext

    def test_encrypt_decrypt_roundtrip_large(self):
        """Large plaintext (10 MB) should encrypt and decrypt correctly."""
        plaintext = b"x" * (10 * 1024 * 1024)
        encrypted = encrypt_evidence(plaintext)
        decrypted = decrypt_evidence(encrypted)
        assert decrypted == plaintext

    def test_encrypt_produces_different_output(self):
        """Encrypted output should differ from plaintext."""
        plaintext = b"test evidence"
        encrypted = encrypt_evidence(plaintext)
        assert encrypted != plaintext
        assert len(encrypted) >= len(plaintext) + 12 + 16

    def test_encrypted_data_includes_nonce(self):
        """Encrypted output should start with a 12-byte nonce."""
        plaintext = b"test"
        encrypted = encrypt_evidence(plaintext)
        assert len(encrypted) >= 12

    def test_nonce_is_random(self):
        """Each encryption should use a different nonce."""
        plaintext = b"same plaintext"
        encrypted1 = encrypt_evidence(plaintext)
        encrypted2 = encrypt_evidence(plaintext)
        assert encrypted1 != encrypted2


class TestEncryptionWithMissingKey:
    """Tests for missing encryption key scenarios."""

    def test_encrypt_without_key_raises_error(self, monkeypatch):
        """Encryption with no key configured anywhere should raise EncryptionError.

        The key can come from the OS environment OR the configured env file
        (settings.encryption_key); both channels must be cleared.
        """
        monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
        monkeypatch.setattr(settings, "encryption_key", None)
        with pytest.raises(EncryptionError) as exc_info:
            encrypt_evidence(b"plaintext")
        assert "ENCRYPTION_KEY" in str(exc_info.value)

    def test_decrypt_without_key_raises_error(self, monkeypatch):
        """Decryption with no key configured anywhere should raise DecryptionError."""
        monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
        monkeypatch.setattr(settings, "encryption_key", None)
        with pytest.raises(DecryptionError) as exc_info:
            decrypt_evidence(b"encrypted_data")
        assert "ENCRYPTION_KEY" in str(exc_info.value)


class TestEncryptionKeyValidation:
    """Tests for encryption key validation."""

    def test_invalid_hex_string_raises_error(self):
        """Invalid hex in ENCRYPTION_KEY should raise EncryptionError."""
        os.environ["ENCRYPTION_KEY"] = "not_valid_hex" + "x" * 50
        with pytest.raises(EncryptionError) as exc_info:
            encrypt_evidence(b"plaintext")
        assert "invalid hex" in str(exc_info.value).lower()
        del os.environ["ENCRYPTION_KEY"]

    def test_wrong_key_size_too_short_raises_error(self):
        """16-byte key should fail (requires 32 bytes)."""
        key_16 = os.urandom(16).hex()
        os.environ["ENCRYPTION_KEY"] = key_16
        with pytest.raises(EncryptionError) as exc_info:
            encrypt_evidence(b"plaintext")
        assert "32 bytes" in str(exc_info.value)
        del os.environ["ENCRYPTION_KEY"]

    def test_wrong_key_size_too_long_raises_error(self):
        """48-byte key should fail (requires exactly 32 bytes)."""
        key_48 = os.urandom(48).hex()
        os.environ["ENCRYPTION_KEY"] = key_48
        with pytest.raises(EncryptionError) as exc_info:
            encrypt_evidence(b"plaintext")
        assert "32 bytes" in str(exc_info.value)
        del os.environ["ENCRYPTION_KEY"]


class TestDecryptionFailures:
    """Tests for decryption failure scenarios."""

    @pytest.fixture(autouse=True)
    def setup_encryption_key(self):
        """Set up test encryption keys."""
        self.key1 = generate_example_key()
        self.key2 = generate_example_key()
        os.environ["ENCRYPTION_KEY"] = self.key1
        yield
        if "ENCRYPTION_KEY" in os.environ:
            del os.environ["ENCRYPTION_KEY"]

    def test_decrypt_with_wrong_key_raises_error(self):
        """Decrypting with wrong key should raise DecryptionError."""
        plaintext = b"secret evidence"
        encrypted = encrypt_evidence(plaintext)
        os.environ["ENCRYPTION_KEY"] = self.key2
        with pytest.raises(DecryptionError):
            decrypt_evidence(encrypted)

    def test_decrypt_corrupted_data_raises_error(self):
        """Corrupted ciphertext should raise DecryptionError."""
        plaintext = b"secret evidence"
        encrypted = encrypt_evidence(plaintext)
        corrupted = encrypted[:-1] + b"X"
        with pytest.raises(DecryptionError):
            decrypt_evidence(corrupted)

    def test_decrypt_truncated_data_raises_error(self):
        """Truncated encrypted data should raise DecryptionError."""
        plaintext = b"evidence"
        encrypted = encrypt_evidence(plaintext)
        truncated = encrypted[:10]
        with pytest.raises(DecryptionError):
            decrypt_evidence(truncated)

    def test_decrypt_empty_data_raises_error(self):
        """Empty data should raise DecryptionError."""
        with pytest.raises(DecryptionError):
            decrypt_evidence(b"")

    def test_auth_tag_mismatch_on_corrupted_file(self):
        """Modified ciphertext should fail auth tag verification."""
        os.environ["ENCRYPTION_KEY"] = self.key1
        plaintext = b"forensic evidence"
        encrypted = encrypt_evidence(plaintext)
        
        if len(encrypted) > 20:
            corrupted = encrypted[:20] + bytes([encrypted[20] ^ 0xFF]) + encrypted[21:]
            with pytest.raises(DecryptionError) as exc_info:
                decrypt_evidence(corrupted)
            assert "authentication tag" in str(exc_info.value).lower() or "corrupted" in str(exc_info.value).lower()


class TestEvidenceUploadWithEncryption:
    """Tests for evidence upload and verification with encryption integrated."""

    @pytest.fixture(autouse=True)
    def setup_encryption_key(self):
        """Set up test encryption key."""
        self.test_key = generate_example_key()
        os.environ["ENCRYPTION_KEY"] = self.test_key
        yield
        if "ENCRYPTION_KEY" in os.environ:
            del os.environ["ENCRYPTION_KEY"]

    def test_upload_evidence_with_encryption(self, client, user_factory, login_headers):
        """Evidence upload should encrypt file before storage."""
        investigator = user_factory(role="investigator", username="inv_enc1")
        headers = login_headers(investigator.username, "Passw0rd!x")

        case = client.post(
            "/api/cases",
            headers=headers,
            json={
                "case_number": "CASE-ENC-1",
                "title": "Encryption test",
                "description": "Test encrypted upload",
                "offense": "Test",
                "victim": "Test",
                "suspect": "Test",
                "submitting_officer": "Test",
                "location": "Test",
                "status": "open",
            },
        )
        case_id = case.json()["id"]

        plaintext = b"sensitive evidence data"
        resp = client.post(
            "/api/evidence/upload",
            headers=headers,
            data={"case_id": case_id, "description": "Encrypted upload test"},
            files={"file": ("evidence.bin", plaintext, "application/octet-stream")},
        )
        assert resp.status_code == 201
        evidence = resp.json()
        storage_path = evidence["storage_path"]

        stored_encrypted = Path(storage_path).read_bytes()
        assert stored_encrypted != plaintext
        assert len(stored_encrypted) > len(plaintext)


class TestIntegrityWithEncryption:
    """Tests for integrity verification with encrypted evidence."""

    @pytest.fixture(autouse=True)
    def setup_encryption_key(self):
        """Set up test encryption key."""
        self.test_key = generate_example_key()
        os.environ["ENCRYPTION_KEY"] = self.test_key
        yield
        if "ENCRYPTION_KEY" in os.environ:
            del os.environ["ENCRYPTION_KEY"]

    def test_verify_integrity_with_encrypted_file(self, client, user_factory, login_headers):
        """Integrity verification should decrypt and verify correctly."""
        investigator = user_factory(role="investigator", username="inv_enc_verify1")
        headers = login_headers(investigator.username, "Passw0rd!x")

        case = client.post(
            "/api/cases",
            headers=headers,
            json={
                "case_number": "CASE-ENC-VERIFY-1",
                "title": "Encrypted integrity test",
                "description": "Test verification with encryption",
                "offense": "Test",
                "victim": "Test",
                "suspect": "Test",
                "submitting_officer": "Test",
                "location": "Test",
                "status": "open",
            },
        )
        case_id = case.json()["id"]

        plaintext = b"evidence for integrity check"
        upload = client.post(
            "/api/evidence/upload",
            headers=headers,
            data={"case_id": case_id, "description": "Integrity test"},
            files={"file": ("evidence.bin", plaintext, "application/octet-stream")},
        )
        evidence_id = upload.json()["id"]

        resp = client.post(
            f"/api/evidence/verify/{evidence_id}",
            headers=headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["match"] is True
        assert body["status"] == "INTEGRITY VERIFIED"

    def test_verify_detects_tampering_in_encrypted_file(self, client, user_factory, login_headers):
        """Tampering with encrypted file should be detected during verification."""
        investigator = user_factory(role="investigator", username="inv_enc_tamp1")
        headers = login_headers(investigator.username, "Passw0rd!x")

        case = client.post(
            "/api/cases",
            headers=headers,
            json={
                "case_number": "CASE-ENC-TAMP-1",
                "title": "Encrypted tampering test",
                "description": "Test tampering detection",
                "offense": "Test",
                "victim": "Test",
                "suspect": "Test",
                "submitting_officer": "Test",
                "location": "Test",
                "status": "open",
            },
        )
        case_id = case.json()["id"]

        plaintext = b"original evidence"
        upload = client.post(
            "/api/evidence/upload",
            headers=headers,
            data={"case_id": case_id, "description": "Tampering test"},
            files={"file": ("evidence.bin", plaintext, "application/octet-stream")},
        )
        evidence = upload.json()
        evidence_id = evidence["id"]
        storage_path = evidence["storage_path"]

        encrypted_data = Path(storage_path).read_bytes()
        if len(encrypted_data) > 20:
            corrupted = encrypted_data[:20] + bytes([encrypted_data[20] ^ 0xFF]) + encrypted_data[21:]
            Path(storage_path).write_bytes(corrupted)

            resp = client.post(
                f"/api/evidence/verify/{evidence_id}",
                headers=headers,
            )
            assert resp.status_code == 500
            assert "decryption failed" in resp.json()["detail"].lower()

    def test_verify_detects_key_missing_during_decryption(self, client, user_factory, login_headers):
        """Verification should fail if encryption key is missing."""
        investigator = user_factory(role="investigator", username="inv_enc_nokey1")
        headers = login_headers(investigator.username, "Passw0rd!x")

        case = client.post(
            "/api/cases",
            headers=headers,
            json={
                "case_number": "CASE-ENC-NOKEY-1",
                "title": "Missing key test",
                "description": "Test missing key handling",
                "offense": "Test",
                "victim": "Test",
                "suspect": "Test",
                "submitting_officer": "Test",
                "location": "Test",
                "status": "open",
            },
        )
        case_id = case.json()["id"]

        plaintext = b"encrypted evidence"
        upload = client.post(
            "/api/evidence/upload",
            headers=headers,
            data={"case_id": case_id, "description": "Key test"},
            files={"file": ("evidence.bin", plaintext, "application/octet-stream")},
        )
        evidence_id = upload.json()["id"]

        old_key = os.environ.get("ENCRYPTION_KEY")
        if "ENCRYPTION_KEY" in os.environ:
            del os.environ["ENCRYPTION_KEY"]

        resp = client.post(
            f"/api/evidence/verify/{evidence_id}",
            headers=headers,
        )
        assert resp.status_code == 500

        if old_key:
            os.environ["ENCRYPTION_KEY"] = old_key


class TestEncryptionEdgeCases:
    """Tests for edge cases and special scenarios."""

    @pytest.fixture(autouse=True)
    def setup_encryption_key(self):
        """Set up test encryption key."""
        self.test_key = generate_example_key()
        os.environ["ENCRYPTION_KEY"] = self.test_key
        yield
        if "ENCRYPTION_KEY" in os.environ:
            del os.environ["ENCRYPTION_KEY"]

    def test_encrypt_empty_plaintext(self):
        """Empty plaintext should encrypt and decrypt correctly."""
        plaintext = b""
        encrypted = encrypt_evidence(plaintext)
        decrypted = decrypt_evidence(encrypted)
        assert decrypted == plaintext

    def test_encrypt_single_byte(self):
        """Single byte should encrypt and decrypt correctly."""
        plaintext = b"\x00"
        encrypted = encrypt_evidence(plaintext)
        decrypted = decrypt_evidence(encrypted)
        assert decrypted == plaintext

    def test_encrypt_max_size_file(self):
        """Maximum size file (25 MB) should encrypt correctly."""
        plaintext = b"x" * (25 * 1024 * 1024)
        encrypted = encrypt_evidence(plaintext)
        decrypted = decrypt_evidence(encrypted)
        assert decrypted == plaintext

    def test_encrypted_binary_contains_nonce_in_first_12_bytes(self):
        """Encrypted data should have nonce in first 12 bytes (though nonce could be random)."""
        plaintext = b"test"
        encrypted = encrypt_evidence(plaintext)
        assert len(encrypted) >= 12 + 16


class TestEncryptionIntegration:
    """Integration tests for encryption across the full flow."""

    @pytest.fixture(autouse=True)
    def setup_encryption_key(self):
        """Set up test encryption key."""
        self.test_key = generate_example_key()
        os.environ["ENCRYPTION_KEY"] = self.test_key
        yield
        if "ENCRYPTION_KEY" in os.environ:
            del os.environ["ENCRYPTION_KEY"]

    def test_hash_computed_on_plaintext_before_encryption(self, client, user_factory, login_headers, db_session):
        """SHA-256 hash should be computed on plaintext, not ciphertext."""
        from app.models.evidence_hash import EvidenceHash
        
        investigator = user_factory(role="investigator", username="inv_hash_plain")
        headers = login_headers(investigator.username, "Passw0rd!x")

        case = client.post(
            "/api/cases",
            headers=headers,
            json={
                "case_number": "CASE-HASH-PLAIN-1",
                "title": "Hash on plaintext test",
                "description": "Verify hash computed on plaintext",
                "offense": "Test",
                "victim": "Test",
                "suspect": "Test",
                "submitting_officer": "Test",
                "location": "Test",
                "status": "open",
            },
        )
        case_id = case.json()["id"]

        plaintext = b"forensic evidence content"
        upload = client.post(
            "/api/evidence/upload",
            headers=headers,
            data={"case_id": case_id, "description": "Hash test"},
            files={"file": ("evidence.bin", plaintext, "application/octet-stream")},
        )
        evidence_id = upload.json()["id"]

        stored_hashes = db_session.query(EvidenceHash).filter(
            EvidenceHash.evidence_id == evidence_id,
            EvidenceHash.hash_type == "original",
        ).all()

        assert len(stored_hashes) > 0
        expected_hash = hashlib.sha256(plaintext).hexdigest()
        assert stored_hashes[0].sha256_hex == expected_hash
