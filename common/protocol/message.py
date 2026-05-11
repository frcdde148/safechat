"""统一的 SafeChat JSON 协议封装。"""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from common.protocol.actions import ALL_TYPES


PROTOCOL_VERSION = 1
NONCE_BYTES = 8


@dataclass(slots=True)
class Message:
    """SafeChat 各协议层共用的消息封装。"""

    type: str
    seq: int
    body: dict[str, Any] = field(default_factory=dict)
    sid: str = ""
    v: int = PROTOCOL_VERSION
    ts: int = field(default_factory=lambda: int(time.time() * 1000))
    nonce: str = field(default_factory=lambda: os.urandom(NONCE_BYTES).hex())
    hmac: str = ""
    sig: str = ""
    pubkey: str = ""

    def to_dict(self) -> dict[str, Any]:
        """返回可 JSON 序列化的字典。"""
        validate_message(asdict(self))
        return asdict(self)

    def to_json(self) -> str:
        """将消息序列化为紧凑确定性 JSON 字符串。"""
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))


def encrypted_body(ciphertext_b64: str, iv_b64: str) -> dict[str, str]:
    """构建数据消息所用的加密体形式。"""
    return {"_cipher": ciphertext_b64, "_iv": iv_b64}


def b64(data: bytes) -> str:
    """返回二进制协议字段的 Base64 编码。"""
    return base64.b64encode(data).decode("ascii")


def from_json(raw: str | bytes) -> dict[str, Any]:
    """解析并验证一条 SafeChat JSON 消息。"""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    message = json.loads(raw)
    validate_message(message)
    return message


def validate_message(message: dict[str, Any]) -> None:
    """路由前验证公共封装字段。"""
    required = {"v", "type", "seq", "sid", "ts", "nonce", "body", "hmac", "sig", "pubkey"}
    missing = required - message.keys()
    if missing:
        raise ValueError(f"missing protocol field(s): {sorted(missing)}")

    if message["v"] != PROTOCOL_VERSION:
        raise ValueError(f"unsupported protocol version: {message['v']}")
    if message["type"] not in ALL_TYPES:
        raise ValueError(f"unknown message type: {message['type']}")
    if not isinstance(message["seq"], int) or message["seq"] < 0:
        raise ValueError("seq must be a non-negative integer")
    if not isinstance(message["sid"], str):
        raise ValueError("sid must be a string")
    if not isinstance(message["ts"], int):
        raise ValueError("ts must be an integer timestamp in milliseconds")
    if not isinstance(message["nonce"], str) or len(message["nonce"]) != NONCE_BYTES * 2:
        raise ValueError("nonce must be 16 hex characters")
    int(message["nonce"], 16)
    if not isinstance(message["body"], dict):
        raise ValueError("body must be an object")
    for field_name in ("hmac", "sig", "pubkey"):
        if not isinstance(message[field_name], str):
            raise ValueError(f"{field_name} must be a string")
