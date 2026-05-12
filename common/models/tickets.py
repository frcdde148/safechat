"""共享数据模型，包括票据与认证子。"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
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


def ticket_plaintext(ticket: Ticket) -> dict[str, Any]:
    """将票据转换为教材里的标准 Kerberos plaintext 结构。"""
    payload: dict[str, Any] = {
        "id_c": ticket.client_id,
        "ad_c": ticket.client_addr,
    }
    if ticket.service_id == "tgs_server":
        payload.update(
            {
                "k_c_tgs": ticket.session_key,
                "id_tgs": ticket.service_id,
                "ts_2": ticket.issued_at,
                "lifetime_2": ticket.expires_at,
            }
        )
    elif ticket.service_id == "chat_server":
        payload.update(
            {
                "k_c_v": ticket.session_key,
                "id_v": ticket.service_id,
                "ts_4": ticket.issued_at,
                "lifetime_4": ticket.expires_at,
            }
        )
    else:
        payload.update(
            {
                "session_key": ticket.session_key,
                "service_id": ticket.service_id,
                "issued_at": ticket.issued_at,
                "expires_at": ticket.expires_at,
            }
        )
    return payload


def authenticator_plaintext(authenticator: Authenticator, timestamp_field: str = "ts_3") -> dict[str, Any]:
    """将认证子转换为标准 Kerberos plaintext 结构。"""
    return {
        "id_c": authenticator.client_id,
        "ad_c": authenticator.client_addr,
        timestamp_field: authenticator.timestamp,
    }


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
    if isinstance(model, Ticket):
        payload = ticket_plaintext(model)
    elif isinstance(model, Authenticator):
        payload = authenticator_plaintext(model)
    else:
        payload = model
    return encrypt_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), secret)


def encrypt_ticket(ticket: Ticket, secret: str) -> dict[str, str]:
    """加密票据并输出标准 Kerberos JSON 载荷。"""
    return encrypt_model(ticket, secret)


def encrypt_authenticator(authenticator: Authenticator, secret: str, timestamp_field: str = "ts_3") -> dict[str, str]:
    """加密认证子并允许指定时间戳字段名。"""
    payload = authenticator_plaintext(authenticator, timestamp_field=timestamp_field)
    return encrypt_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), secret)


def decrypt_ticket(encrypted: dict[str, str], secret: str) -> Ticket:
    """解密一个票据对象。"""
    payload = _decrypt_dict(encrypted, secret)
    return Ticket(
        client_id=str(payload.get("id_c", payload.get("client_id", ""))),
        client_addr=str(payload.get("ad_c", payload.get("client_addr", ""))),
        session_key=str(
            payload.get("k_c_tgs")
            or payload.get("k_c_v")
            or payload.get("session_key", "")
        ),
        service_id=str(payload.get("id_tgs", payload.get("id_v", payload.get("service_id", "")))),
        issued_at=int(payload.get("ts_2", payload.get("ts_4", payload.get("issued_at", 0)))),
        expires_at=int(payload.get("lifetime_2", payload.get("lifetime_4", payload.get("expires_at", 0)))),
        client_pubkey=str(payload.get("client_pubkey", "")),
    )


def decrypt_authenticator(encrypted: dict[str, str], secret: str) -> Authenticator:
    """解密一个认证子对象。"""
    payload = _decrypt_dict(encrypted, secret)
    return Authenticator(
        client_id=str(payload.get("id_c", payload.get("client_id", ""))),
        client_addr=str(payload.get("ad_c", payload.get("client_addr", ""))),
        timestamp=int(
            payload.get(
                "ts_5",
                payload.get("ts_3", payload.get("ts_1", payload.get("timestamp", 0))),
            )
        ),
    )


def _decrypt_dict(encrypted: dict[str, str], secret: str) -> dict[str, Any]:
    plaintext = decrypt_text(encrypted["ciphertext"], encrypted["iv"], secret)
    return json.loads(plaintext)
