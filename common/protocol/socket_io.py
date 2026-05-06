"""Length-prefixed JSON socket helpers."""

from __future__ import annotations

import socket
import struct
from typing import Any

from common.protocol.message import Message, from_json


HEADER_SIZE = 4
MAX_MESSAGE_SIZE = 4 * 1024 * 1024


def send_message(sock: socket.socket, message: Message | dict[str, Any]) -> None:
    """Send a Message or validated message dict with a 4-byte length prefix."""
    if isinstance(message, Message):
        payload = message.to_json().encode("utf-8")
    else:
        payload = Message(**message).to_json().encode("utf-8")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_message(sock: socket.socket) -> dict[str, Any]:
    """Receive one length-prefixed JSON protocol message."""
    header = _recv_exact(sock, HEADER_SIZE)
    size = struct.unpack("!I", header)[0]
    if size <= 0 or size > MAX_MESSAGE_SIZE:
        raise ValueError(f"invalid message size: {size}")
    return from_json(_recv_exact(sock, size))


def request(host: str, port: int, message: Message, timeout: float = 5.0) -> dict[str, Any]:
    """Open a short TCP connection, send one message, and receive one response."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        send_message(sock, message)
        return recv_message(sock)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("socket closed before full message was received")
        chunks.extend(chunk)
    return bytes(chunks)
