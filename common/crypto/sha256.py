"""SHA-256 digest helpers for salted passwords and integrity checks."""

from __future__ import annotations

import hashlib
import hmac
import os


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 hex digest for bytes."""
    return hashlib.sha256(data).hexdigest()


def new_salt_hex(size: int = 32) -> str:
    """Return a random password salt encoded as hex."""
    return os.urandom(size).hex()


def salted_password_hash(password: str, salt_hex: str) -> str:
    """Hash a password with the project-standard SHA-256 salt format."""
    return sha256_hex(bytes.fromhex(salt_hex) + password.encode("utf-8"))


def verify_password(password: str, salt_hex: str, expected_hash: str) -> bool:
    """Safely compare a plaintext password against a stored salted hash."""
    return hmac.compare_digest(salted_password_hash(password, salt_hex), expected_hash)
