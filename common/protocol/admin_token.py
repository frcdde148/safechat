"""跨服务器管理 API 的带签名管理员令牌工具。"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

from common.config.settings import load_settings
from common.crypto.sha256 import hmac_sha256, hmac_compare_digest


def issue_admin_token(username: str, lifetime_seconds: int = 3600) -> str:
    """当前用户签发一个带时间限制的管理员令牌。"""
    payload = {
        "username": username,
        "expires_at": int(time.time() * 1000) + lifetime_seconds * 1000,
    }
    payload_b64 = _b64(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    signature = _sign(payload_b64)
    return f"{payload_b64}.{signature}"


def verify_admin_token(token: str) -> dict[str, Any] | None:
    """如果签名有效且未过期，返回令牌载荷；否则返回 None。"""
    try:
        payload_b64, signature = token.split(".", 1)
    except ValueError:
        return None
    if not hmac_compare_digest(signature, _sign(payload_b64)):
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(_pad(payload_b64)).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None
    if int(payload.get("expires_at", 0)) < int(time.time() * 1000):
        return None
    return payload


def _sign(payload_b64: str) -> str:
    secret = str(load_settings()["security"].get("admin_token_secret", "safechat-admin-token-secret"))
    digest = hmac_sha256(secret.encode("utf-8"), payload_b64.encode("ascii"))
    return _b64(digest)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _pad(value: str) -> bytes:
    return (value + "=" * (-len(value) % 4)).encode("ascii")
