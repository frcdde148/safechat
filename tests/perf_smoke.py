"""SafeChat 性能 smoke 测试。

运行方式：
    python tests/perf_smoke.py

该脚本使用临时数据库和真实 TCP 服务，输出关键路径耗时。
阈值刻意宽松，用于发现明显性能回退。
"""

from __future__ import annotations

import base64
import json
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, TypeVar


PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUTH_STAGES = ("C_AS_REQ", "AS_C_REP", "C_TGS_REQ", "TGS_C_REP", "C_V_REQ", "V_C_REP")
T = TypeVar("T")


def main() -> int:
    results = []
    results.extend(_run_perf_case("图片不加密", encrypt_images=False))
    results.extend(_run_perf_case("图片加密", encrypt_images=True))

    print("\n性能结果：")
    for name, elapsed_ms in results:
        print(f"- {name}: {elapsed_ms:.1f} ms")

    _assert_under(results, "空轮询平均", 300.0)
    _assert_under(results, "USER_LIST 缓存平均", 300.0)
    _assert_under(results, "最近历史页", 2000.0)
    return 0


def _run_perf_case(label: str, encrypt_images: bool) -> list[tuple[str, float]]:
    with tempfile.TemporaryDirectory(prefix="safechat-perf-", ignore_cleanup_errors=True) as tmp:
        tmp_path = Path(tmp)
        ports = _allocate_ports(3)
        settings_path = _write_settings(tmp_path, ports, encrypt_images)
        env = os.environ.copy()
        env["SAFECHAT_SETTINGS_PATH"] = str(settings_path)
        env["PYTHONUNBUFFERED"] = "1"

        processes: list[subprocess.Popen[str]] = []
        try:
            processes = [
                _start_server("server.as_server.main", env),
                _start_server("server.tgs_server.main", env),
                _start_server("server.chat_server.main", env),
            ]
            _wait_for_port("127.0.0.1", ports["as"], "AS")
            _wait_for_port("127.0.0.1", ports["tgs"], "TGS")
            _wait_for_port("127.0.0.1", ports["chat"], "ChatServer")
            return _measure_scenarios(label, ports, tmp_path)
        finally:
            for process in processes:
                _stop_process(process)


def _write_settings(tmp_path: Path, ports: dict[str, int], encrypt_images: bool) -> Path:
    settings = {
        "as_server": {"bind_host": "127.0.0.1", "public_host": "127.0.0.1", "port": ports["as"]},
        "tgs_server": {
            "bind_host": "127.0.0.1",
            "public_host": "127.0.0.1",
            "port": ports["tgs"],
            "service_key": "perf-tgs-key",
        },
        "chat_server": {
            "bind_host": "127.0.0.1",
            "public_host": "127.0.0.1",
            "port": ports["chat"],
            "service_name": "chat_server",
            "service_key": "perf-chat-key",
        },
        "database": {
            "path": str(tmp_path / "chatroom.db"),
            "as_path": str(tmp_path / "as.db"),
            "tgs_path": str(tmp_path / "tgs.db"),
            "chat_path": str(tmp_path / "chat.db"),
        },
        "logs": {
            "auth_log": str(tmp_path / "auth.log"),
            "chat_log": str(tmp_path / "chat.log"),
            "audit_log": str(tmp_path / "audit.log"),
        },
        "security": {
            "password_hash": "sha256",
            "signature": "rsa-1024",
            "ticket_cipher": "des",
            "audit_content_cipher": "des",
            "admin_token_secret": "safechat-perf-admin-token-secret",
        },
        "performance": {
            "history_page_size": 80,
            "encrypt_images": encrypt_images,
        },
    }
    path = tmp_path / "settings.json"
    path.write_text(json.dumps(settings, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _measure_scenarios(label: str, ports: dict[str, int], tmp_path: Path) -> list[tuple[str, float]]:
    os.environ["SAFECHAT_SETTINGS_PATH"] = str(tmp_path / "settings.json")
    sys.path.insert(0, str(PROJECT_ROOT))

    from client.net.auth_client import AuthClient

    alice = _login(AuthClient, "alice", "alice123", ports)
    bob = _login(AuthClient, "bob", "bob123", ports)
    admin = _login(AuthClient, "admin", "admin123", ports, client_type="admin_console")

    seed_count = 100
    start = time.perf_counter()
    for idx in range(seed_count):
        alice.send_chat_message(f"perf-{label}-{idx}")
    seed_ms = _elapsed_ms(start)

    bob.reset_session_cursor("group", "")
    _, history_ms = _timed(lambda: bob.poll_chat_messages(history_mode="latest"))

    _, empty_poll_ms = _average_time(lambda: bob.poll_chat_messages(), count=20)
    _, user_list_ms = _average_time(lambda: bob.fetch_online_users(), count=20)
    _, admin_list_ms = _timed(lambda: admin.chat_admin_list_messages(limit=80))

    image_path = tmp_path / "perf.png"
    _write_test_png(image_path, repeat=128)
    image_result, image_send_ms = _timed(lambda: alice.send_image(str(image_path)))
    image_id = int(image_result["message_id"])
    _, image_fetch_ms = _timed(lambda: bob.fetch_message_image(image_id))

    return [
        (f"{label} 写入 {seed_count} 条文本", seed_ms),
        (f"{label} 最近历史页", history_ms),
        (f"{label} 空轮询平均", empty_poll_ms),
        (f"{label} USER_LIST 缓存平均", user_list_ms),
        (f"{label} 控制台查 80 条", admin_list_ms),
        (f"{label} 发送图片", image_send_ms),
        (f"{label} 拉取图片", image_fetch_ms),
    ]


def _timed(fn: Callable[[], T]) -> tuple[T, float]:
    start = time.perf_counter()
    value = fn()
    return value, _elapsed_ms(start)


def _average_time(fn: Callable[[], T], count: int) -> tuple[T, float]:
    values = []
    last_value = None
    for _ in range(count):
        last_value, elapsed = _timed(fn)
        values.append(elapsed)
    return last_value, statistics.mean(values)


def _elapsed_ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000


def _assert_under(results: list[tuple[str, float]], key: str, limit_ms: float) -> None:
    matched = [(name, value) for name, value in results if key in name]
    for name, value in matched:
        assert value < limit_ms, f"{name} 过慢：{value:.1f} ms >= {limit_ms:.1f} ms"


def _login(auth_client_cls, username: str, password: str, ports: dict[str, int], client_type: str = "client"):
    client = auth_client_cls(
        {
            "username": username,
            "password": password,
            "client_type": client_type,
            "as": ("127.0.0.1", ports["as"]),
        }
    )
    for stage in AUTH_STAGES:
        ok, detail = client.run_stage(stage)
        if not ok:
            raise RuntimeError(f"{username} 认证阶段 {stage} 失败：{detail}")
    return client


def _write_test_png(path: Path, repeat: int) -> None:
    png_b64 = (
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8"
        "/x8AAwMCAO+/p9sAAAAASUVORK5CYII="
    )
    data = base64.b64decode(png_b64)
    path.write_bytes(data * max(1, repeat))


def _allocate_ports(count: int) -> dict[str, int]:
    sockets = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            sockets.append(sock)
        values = [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()
    return {"as": values[0], "tgs": values[1], "chat": values[2]}


def _start_server(module: str, env: dict[str, str]) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, "-m", module],
        cwd=PROJECT_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def _wait_for_port(host: str, port: int, name: str, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"{name} 未在 {host}:{port} 启动")


def _stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
