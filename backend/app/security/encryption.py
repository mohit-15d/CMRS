"""Evidence encryption/decryption using AES-256-GCM.

Stage 12 implements secure encryption at rest for digital evidence using
AES-256-GCM (authenticated encryption with associated data).

**Key Management (Academic/Demo Limitation):**
This implementation loads the encryption key from the environment variable
ENCRYPTION_KEY. In a production deployment, the key should be managed by:
- A dedicated key management service (AWS KMS, Azure Key Vault, etc.)
- Hardware security modules (HSM)
- A secrets vault (HashiCorp Vault, etc.)

This demo setup is NOT suitable for production forensic use.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings


class EncryptionError(Exception):
    """Raised when encryption fails."""
    pass


class DecryptionError(Exception):
    """Raised when decryption fails."""
    pass


def _get_encryption_key() -> bytes:
    """Get the AES-256 encryption key.

    Resolution order:
      1. The ``ENCRYPTION_KEY`` OS environment variable (deployment/CI).
      2. The ``ENCRYPTION_KEY`` entry in the configured env file
         (``backend.env``), which pydantic-settings exposes as
         ``settings.encryption_key`` (pydantic-settings does NOT inject
         .env values into ``os.environ``).

    The key must be exactly 32 bytes (256 bits).

    Raises:
        EncryptionError: If the key is missing, invalid format, or wrong size.
    """
    key_hex = os.environ.get("ENCRYPTION_KEY", "").strip()

    if not key_hex and settings.encryption_key is not None:
        key_hex = settings.encryption_key.get_secret_value().strip()

    if not key_hex:
        raise EncryptionError(
            "ENCRYPTION_KEY is not set. "
            "Set it to a 64-character hex string (32 bytes, 256 bits) "
            "either in the environment or in backend.env."
        )

    try:
        key = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise EncryptionError(
            "ENCRYPTION_KEY must be a valid 64-character hex string (32 bytes). "
            f"Got invalid hex: {key_hex[:20]}..."
        ) from exc
    
    if len(key) != 32:
        raise EncryptionError(
            f"ENCRYPTION_KEY must be exactly 32 bytes (256 bits, 64 hex chars). "
            f"Got {len(key)} bytes ({len(key_hex)} hex chars)."
        )
    
    return key


def encrypt_evidence(plaintext: bytes) -> bytes:
    """Encrypt evidence using AES-256-GCM.

    Generates a cryptographically secure nonce, encrypts the plaintext,
    and returns: nonce (12 bytes) + ciphertext + tag (16 bytes appended by
    AESGCM).

    Args:
        plaintext: The evidence file binary to encrypt.

    Returns:
        Encrypted data in the format: nonce || ciphertext || tag

    Raises:
        EncryptionError: If encryption fails or key is missing.
    """
    try:
        key = _get_encryption_key()
    except EncryptionError:
        raise
    
    nonce = os.urandom(12)
    
    cipher = AESGCM(key)
    try:
        ciphertext = cipher.encrypt(nonce, plaintext, None)
    except Exception as exc:
        raise EncryptionError(f"AES-256-GCM encryption failed: {exc}") from exc
    
    return nonce + ciphertext


def decrypt_evidence(encrypted_data: bytes) -> bytes:
    """Decrypt evidence using AES-256-GCM.

    Expects input in format: nonce (12 bytes) + ciphertext + tag (16 bytes).
    Validates the authentication tag during decryption.

    Args:
        encrypted_data: The encrypted evidence in nonce || ciphertext || tag format.

    Returns:
        The original plaintext evidence bytes.

    Raises:
        DecryptionError: If decryption fails, key is missing, or auth tag fails.
    """
    try:
        key = _get_encryption_key()
    except EncryptionError as exc:
        raise DecryptionError(str(exc)) from exc
    
    if len(encrypted_data) < 12 + 16:
        raise DecryptionError(
            f"Encrypted data too short. Expected at least {12 + 16} bytes "
            f"(nonce + tag), got {len(encrypted_data)} bytes."
        )
    
    nonce = encrypted_data[:12]
    ciphertext_and_tag = encrypted_data[12:]
    
    cipher = AESGCM(key)
    try:
        plaintext = cipher.decrypt(nonce, ciphertext_and_tag, None)
    except Exception as exc:
        raise DecryptionError(
            f"AES-256-GCM decryption failed (possibly corrupted file or "
            f"authentication tag mismatch): {exc}"
        ) from exc
    
    return plaintext


def generate_example_key() -> str:
    """Generate a random 256-bit encryption key as hex for demo/setup purposes.

    Returns:
        A 64-character hex string representing a random 256-bit key.
    """
    key = os.urandom(32)
    return key.hex()
