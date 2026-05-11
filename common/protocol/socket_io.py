"""带长度前缀的 JSON 套接字工具。"""

from __future__ import annotations

import socket
import struct
from typing import Any

from common.protocol.message import Message, from_json


HEADER_SIZE = 4
MAX_MESSAGE_SIZE = 4 * 1024 * 1024


def send_message(sock: socket.socket, message: Message | dict[str, Any]) -> None:
    """发送一条消息，带 4 字节长度前缀。"""
    if isinstance(message, Message):
        payload = message.to_json().encode("utf-8")
    else:
        payload = Message(**message).to_json().encode("utf-8")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_message(sock: socket.socket) -> dict[str, Any]:
    """接收一条带长度前缀的 JSON 协议消息。"""
    header = _recv_exact(sock, HEADER_SIZE)
    size = struct.unpack("!I", header)[0]
    if size <= 0 or size > MAX_MESSAGE_SIZE:
        raise ValueError(f"invalid message size: {size}")
    return from_json(_recv_exact(sock, size))


def request(host: str, port: int, message: Message, timeout: float = 5.0) -> dict[str, Any]:
    """建立短路 TCP 连接，发送一条消息并接收一条响应。"""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        send_message(sock, message)
        return recv_message(sock)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("套接字已关闭，未收到完整消息")
        chunks.extend(chunk)
    return bytes(chunks)
