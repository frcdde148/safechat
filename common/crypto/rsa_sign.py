"""RSA-1024 signing and verification helpers.

The implementation will wrap a mature crypto library. Keep RSA usage focused
on non-repudiation for key chat and file actions, not bulk encryption.
"""

from __future__ import annotations

import base64

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


SIGNED_ACTIONS = {
    "CHAT_SEND",
    "CHAT_RECV",
    "CHAT_ACK",
    "FILE_SEND",
    "FILE_RECV",
    "FILE_ACK",
}


def generate_key_pair(bits: int = 1024) -> tuple[str, str]:
    """Generate a PEM encoded RSA private/public key pair."""
    key = RSA.generate(bits)
    return (
        key.export_key().decode("ascii"),
        key.publickey().export_key().decode("ascii"),
    )


def sign_text(text: str, private_key_pem: str) -> str:
    """Sign text and return a Base64 RSA signature."""
    key = RSA.import_key(private_key_pem)
    digest = SHA256.new(text.encode("utf-8"))
    return base64.b64encode(pkcs1_15.new(key).sign(digest)).decode("ascii")


def verify_text(text: str, signature_b64: str, public_key_pem: str) -> bool:
    """Verify a Base64 RSA signature against text."""
    try:
        key = RSA.import_key(public_key_pem)
        digest = SHA256.new(text.encode("utf-8"))
        pkcs1_15.new(key).verify(digest, base64.b64decode(signature_b64))
        return True
    except (ValueError, TypeError):
        return False
