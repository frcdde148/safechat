"""DES encryption and decryption helpers."""

from __future__ import annotations

import base64
import hashlib

from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


BLOCK_SIZE = 8


def derive_des_key(secret: str | bytes) -> bytes:
    """Derive a DES-sized key from a text or binary secret."""
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hashlib.sha256(secret).digest()[:BLOCK_SIZE]


def encrypt_text(plaintext: str, secret: str | bytes) -> dict[str, str]:
    """Encrypt UTF-8 text with DES-CBC and return Base64 fields."""
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = DES.new(derive_des_key(secret), DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), BLOCK_SIZE))
    return {
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
    }


def decrypt_text(ciphertext_b64: str, iv_b64: str, secret: str | bytes) -> str:
    """Decrypt Base64 DES-CBC fields into UTF-8 text."""
    cipher = DES.new(derive_des_key(secret), DES.MODE_CBC, base64.b64decode(iv_b64))
    plaintext = unpad(cipher.decrypt(base64.b64decode(ciphertext_b64)), BLOCK_SIZE)
    return plaintext.decode("utf-8")
