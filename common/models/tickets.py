"""共享数据模型，包括票据与认证子。"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from typing import Any

from common.crypto.des import decrypt_text, encrypt_text


DEFAULT_TICKET_LIFETIME_MS = 30 * 60 * 1000
DEFAULT_CLOCK_SKEW_MS = 5 * 60 * 1000


@dataclass(slots=True)
class Ticket:
    """Kerberos 风格的加密服务票据载荷。"""

    client_id: str
    client_addr: str
    session_key: str
    service_id: str
    issued_at: int
    expires_at: int
    client_pubkey: str = ""

    def is_valid(self, now_ms: int | None = None, skew_ms: int = DEFAULT_CLOCK_SKEW_MS) -> bool:
        """判断票据是否在有效期内（允许一定时钟偏差）。"""
        now_ms = now_ms or int(time.time() * 1000)
        return self.issued_at - skew_ms <= now_ms <= self.expires_at + skew_ms

    def validity_debug(self, now_ms: int | None = None) -> dict[str, int]:
        """返回时间戳调试信息，用于诊断多主机时钟偏差。"""
        now_ms = now_ms or int(time.time() * 1000)
        return {
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "now": now_ms,
            "clock_skew_ms": DEFAULT_CLOCK_SKEW_MS,
        }


@dataclass(slots=True)
class Authenticator:
    """Kerberos 风格的加密认证子载荷。"""

    client_id: str
    client_addr: str
    timestamp: int


def issue_ticket(
    client_id: str,
    client_addr: str,
    session_key: str,
    service_id: str,
    client_pubkey: str = "",
) -> Ticket:
    """按项目默认有效期创建一个票据。"""
    now = int(time.time() * 1000)
    return Ticket(
        client_id=client_id,
        client_addr=client_addr,
        session_key=session_key,
        service_id=service_id,
        issued_at=now,
        expires_at=now + DEFAULT_TICKET_LIFETIME_MS,
        client_pubkey=client_pubkey,
    )


def issue_authenticator(client_id: str, client_addr: str) -> Authenticator:
    """创建带当前时间戳的认证子。"""
    return Authenticator(client_id=client_id, client_addr=client_addr, timestamp=int(time.time() * 1000))


def encrypt_model(model: Ticket | Authenticator | dict[str, Any], secret: str) -> dict[str, str]:
    """使用 DES 加密票据/认证子对象。"""
    payload = asdict(model) if not isinstance(model, dict) else model
    return encrypt_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), secret)


def decrypt_ticket(encrypted: dict[str, str], secret: str) -> Ticket:
    """解密一个票据对象。"""
    return Ticket(**_decrypt_dict(encrypted, secret))


def decrypt_authenticator(encrypted: dict[str, str], secret: str) -> Authenticator:
    """解密一个认证子对象。"""
    return Authenticator(**_decrypt_dict(encrypted, secret))


def _decrypt_dict(encrypted: dict[str, str], secret: str) -> dict[str, Any]:
    plaintext = decrypt_text(encrypted["ciphertext"], encrypted["iv"], secret)
    return json.loads(plaintext)
