"""SHA-256 digest helpers for salted passwords and integrity checks."""

from __future__ import annotations

import hashlib


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 hex digest for bytes."""
    return hashlib.sha256(data).hexdigest()
