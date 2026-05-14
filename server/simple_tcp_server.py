"""SafeChat服务的可复用线程TCP服务器"""

from __future__ import annotations

import socket
import threading
from typing import Any, Callable

from common.protocol.message import Message
from common.protocol.socket_io import recv_message, send_message


Handler = Callable[[dict, tuple[str, int]], Message | dict[str, Any]]


def serve(host: str, port: int, service_name: str, handler: Handler) -> None:
    """使用SafeChat帧协议在每个TCP连接上处理一个请求"""
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
    """处理单个客户端连接"""
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
        try:
            send_message(sock, response)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError) as e:
            # 客户端在响应发送前已断开，记录并安全返回，不让线程抛出未捕获异常
            print(f"[warning] 发送响应失败，连接已断开: {e}")
