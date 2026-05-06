"""Reusable threaded TCP server for SafeChat services."""

from __future__ import annotations

import socket
import threading
from typing import Callable

from common.protocol.message import Message
from common.protocol.socket_io import recv_message, send_message


Handler = Callable[[dict, tuple[str, int]], Message]


def serve(host: str, port: int, service_name: str, handler: Handler) -> None:
    """Serve one request per TCP connection using the SafeChat framing protocol."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen()
        print(f"{service_name} listening on {host}:{port}")
        while True:
            client, address = server.accept()
            thread = threading.Thread(
                target=_handle_client,
                args=(client, address, handler),
                daemon=True,
            )
            thread.start()


def _handle_client(sock: socket.socket, address: tuple[str, int], handler: Handler) -> None:
    with sock:
        try:
            request = recv_message(sock)
            response = handler(request, address)
        except Exception as exc:
            response = Message(
                type="ERROR",
                seq=0,
                body={"error": str(exc)},
            )
        send_message(sock, response)
