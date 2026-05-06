"""Shared data models such as tickets and authenticators."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from typing import Any

from common.crypto.des import decrypt_text, encrypt_text


DEFAULT_TICKET_LIFETIME_MS = 10 * 60 * 1000


@dataclass(slots=True)
class Ticket:
    """Kerberos-style encrypted service ticket payload."""

    client_id: str
    client_addr: str
    session_key: str
    service_id: str
    issued_at: int
    expires_at: int

    def is_valid(self, now_ms: int | None = None) -> bool:
        """Return whether the ticket is inside its lifetime."""
        now_ms = now_ms or int(time.time() * 1000)
        return self.issued_at <= now_ms <= self.expires_at


@dataclass(slots=True)
class Authenticator:
    """Kerberos-style encrypted authenticator payload."""

    client_id: str
    client_addr: str
    timestamp: int


def issue_ticket(client_id: str, client_addr: str, session_key: str, service_id: str) -> Ticket:
    """Create a ticket with the project default lifetime."""
    now = int(time.time() * 1000)
    return Ticket(
        client_id=client_id,
        client_addr=client_addr,
        session_key=session_key,
        service_id=service_id,
        issued_at=now,
        expires_at=now + DEFAULT_TICKET_LIFETIME_MS,
    )


def issue_authenticator(client_id: str, client_addr: str) -> Authenticator:
    """Create an authenticator for the current timestamp."""
    return Authenticator(client_id=client_id, client_addr=client_addr, timestamp=int(time.time() * 1000))


def encrypt_model(model: Ticket | Authenticator | dict[str, Any], secret: str) -> dict[str, str]:
    """Encrypt a ticket/authenticator-compatible object with DES."""
    payload = asdict(model) if not isinstance(model, dict) else model
    return encrypt_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), secret)


def decrypt_ticket(encrypted: dict[str, str], secret: str) -> Ticket:
    """Decrypt a ticket object."""
    return Ticket(**_decrypt_dict(encrypted, secret))


def decrypt_authenticator(encrypted: dict[str, str], secret: str) -> Authenticator:
    """Decrypt an authenticator object."""
    return Authenticator(**_decrypt_dict(encrypted, secret))


def _decrypt_dict(encrypted: dict[str, str], secret: str) -> dict[str, Any]:
    plaintext = decrypt_text(encrypted["ciphertext"], encrypted["iv"], secret)
    return json.loads(plaintext)
