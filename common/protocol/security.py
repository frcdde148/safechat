"""Digest and signature helpers for SafeChat protocol messages."""

from __future__ import annotations

import json
from typing import Any

from common.crypto.rsa_sign import sign_text, verify_text
from common.crypto.sha256 import sha256_hex


def canonical_body(body: dict[str, Any]) -> str:
    """Serialize a message body in a deterministic form for digest/signature."""
    return json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def body_digest(body: dict[str, Any]) -> str:
    """Return the SHA-256 digest for a protocol message body."""
    return sha256_hex(canonical_body(body).encode("utf-8"))


def sign_body(body: dict[str, Any], private_key_pem: str) -> tuple[str, str]:
    """Return body digest plus RSA signature over that digest."""
    digest = body_digest(body)
    return digest, sign_text(digest, private_key_pem)


def verify_body_signature(body: dict[str, Any], digest: str, signature: str, public_key_pem: str) -> bool:
    """Verify both body digest and RSA signature."""
    if body_digest(body) != digest:
        return False
    return verify_text(digest, signature, public_key_pem)
