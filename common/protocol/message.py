"""Unified SafeChat JSON protocol envelope."""

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
    """SafeChat message envelope shared by all protocol layers."""

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
        """Return a JSON-serializable dictionary."""
        validate_message(asdict(self))
        return asdict(self)

    def to_json(self) -> str:
        """Serialize the message using compact deterministic JSON."""
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))


def encrypted_body(ciphertext_b64: str, iv_b64: str) -> dict[str, str]:
    """Build the encrypted body shape used by data messages."""
    return {"_cipher": ciphertext_b64, "_iv": iv_b64}


def b64(data: bytes) -> str:
    """Return Base64 text for binary protocol fields."""
    return base64.b64encode(data).decode("ascii")


def from_json(raw: str | bytes) -> dict[str, Any]:
    """Decode and validate a SafeChat JSON message."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    message = json.loads(raw)
    validate_message(message)
    return message


def validate_message(message: dict[str, Any]) -> None:
    """Validate the common envelope fields before routing."""
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
