"""用于 SafeChat 协议消息的摘要与签名工具。"""

from __future__ import annotations

import json
from typing import Any

from common.crypto.rsa_sign import sign_text, verify_text
from common.crypto.sha256 import sha256_hex


def canonical_body(body: dict[str, Any]) -> str:
    """将消息体按确定性方式序列化，用于计算摘要和签名。"""
    return json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def body_digest(body: dict[str, Any]) -> str:
    """返回协议消息体的 SHA-256 摘要。"""
    return sha256_hex(canonical_body(body).encode("utf-8"))


def sign_body(body: dict[str, Any], private_key_pem: str) -> tuple[str, str]:
    """返回消息体摘要及对该摘要的 RSA 签名。"""
    digest = body_digest(body)
    return digest, sign_text(digest, private_key_pem)


def verify_body_signature(body: dict[str, Any], digest: str, signature: str, public_key_pem: str) -> bool:
    """同时验证消息体摘要和 RSA 签名。"""
    if body_digest(body) != digest:
        return False
    return verify_text(digest, signature, public_key_pem)
