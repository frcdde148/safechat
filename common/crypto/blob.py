"""大字段二进制加密工具。

图片和文件不再使用纯 Python DES 加密 Base64 文本，而是直接对 bytes 使用
AES-GCM。AES-GCM 同时提供机密性和完整性校验，适合图片这类较大的正文。
"""

from __future__ import annotations

import base64

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from common.crypto.sha256 import sha256_bytes


ALG = "AES-256-GCM"
NONCE_SIZE = 12
KEY_SIZE = 32


def derive_aes_key(secret: str | bytes) -> bytes:
    """从会话密钥或服务密钥派生 AES-256 密钥。"""
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return sha256_bytes(secret)[:KEY_SIZE]


def encrypt_blob(data: bytes, secret: str | bytes) -> dict[str, str]:
    """使用 AES-GCM 加密二进制数据，返回可 JSON 序列化的 Base64 字段。"""
    key = derive_aes_key(secret)
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {
        "alg": ALG,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }


def decrypt_blob(payload: dict[str, str], secret: str | bytes) -> bytes:
    """解密 AES-GCM 二进制密文，并校验认证标签。"""
    if payload.get("alg") != ALG:
        raise ValueError(f"不支持的二进制加密算法：{payload.get('alg', '')}")
    key = derive_aes_key(secret)
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    tag = base64.b64decode(payload["tag"])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
