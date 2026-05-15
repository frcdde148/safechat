"""SafeChat 端到端回归测试。

运行方式：
    python tests/e2e_smoke.py

脚本会使用临时配置、临时数据库和临时端口启动 AS/TGS/ChatServer，
不会修改 common/config/settings.json 或正式数据库。
"""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUTH_STAGES = ("C_AS_REQ", "AS_C_REP", "C_TGS_REQ", "TGS_C_REP", "C_V_REQ", "V_C_REP")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="safechat-e2e-") as tmp:
        tmp_path = Path(tmp)
        ports = _allocate_ports(3)
        settings_path = _write_settings(tmp_path, ports)
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
            _run_scenarios(ports, tmp_path)
        except Exception as exc:
            print(f"[失败] {exc}")
            for process in processes:
                _stop_process(process)
            _print_server_logs(processes)
            return 1
        finally:
            for process in processes:
                _stop_process(process)

    print("[通过] SafeChat 端到端 smoke 测试完成")
    return 0


def _write_settings(tmp_path: Path, ports: dict[str, int]) -> Path:
    settings = {
        "as_server": {
            "bind_host": "127.0.0.1",
            "public_host": "127.0.0.1",
            "port": ports["as"],
        },
        "tgs_server": {
            "bind_host": "127.0.0.1",
            "public_host": "127.0.0.1",
            "port": ports["tgs"],
            "service_key": "e2e-tgs-key",
        },
        "chat_server": {
            "bind_host": "127.0.0.1",
            "public_host": "127.0.0.1",
            "port": ports["chat"],
            "service_name": "chat_server",
            "service_key": "e2e-chat-key",
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
            "admin_token_secret": "safechat-e2e-admin-token-secret",
        },
        "performance": {
            "history_page_size": 80,
            "encrypt_images": False,
        },
    }
    path = tmp_path / "settings.json"
    path.write_text(json.dumps(settings, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _run_scenarios(ports: dict[str, int], tmp_path: Path) -> None:
    os.environ["SAFECHAT_SETTINGS_PATH"] = str(tmp_path / "settings.json")
    sys.path.insert(0, str(PROJECT_ROOT))

    from client.net.auth_client import AuthClient
    from common.protocol.message import Message
    from common.protocol.socket_io import request

    alice = _login(AuthClient, "alice", "alice123", ports)
    bob = _login(AuthClient, "bob", "bob123", ports)

    sent_text = f"e2e 文本消息 {int(time.time())}"
    alice.send_chat_message(sent_text)
    bob_messages = _poll_until(lambda: bob.poll_chat_messages(), lambda messages: _has_text(messages, sent_text))
    assert _has_text(bob_messages, sent_text), "bob 未收到 alice 的群聊文本"

    image_path = tmp_path / "tiny.png"
    _write_tiny_png(image_path)
    image_result = alice.send_image(str(image_path))
    assert image_result["success"], "alice 图片发送失败"
    image_id = int(image_result["message_id"])

    bob.reset_session_cursor("group", "")
    image_messages = _poll_until(lambda: bob.poll_chat_messages(), lambda messages: any(m["id"] == image_id and m.get("has_image") for m in messages))
    assert any(m["id"] == image_id and m.get("has_image") for m in image_messages), "bob 未收到图片占位消息"
    image_payload = bob.fetch_message_image(image_id)
    assert image_payload["image_data"], "IMAGE_FETCH 未返回图片数据"

    offline_text = f"e2e 离线私聊 {int(time.time())}"
    alice.send_chat_message(offline_text, chat_type="private", recipient="carol")
    carol = _login(AuthClient, "carol", "carol123", ports)
    offline_messages = carol.get_offline_messages()
    assert _has_text(offline_messages, offline_text), "carol 登录后未收到离线私聊"

    admin = _login(AuthClient, "admin", "admin123", ports, client_type="admin_console")
    token = admin.request_admin_token()
    assert token, "控制台未获取 admin_token"
    as_users = admin.as_admin_request("AS_ADMIN_LIST_USERS", token).get("users", [])
    assert any(row.get("username") == "alice" for row in as_users), "加密 AS 管理请求未返回用户列表"
    tgs_logs = admin.tgs_admin_request("TGS_ADMIN_AUDIT_QUERY", token, {"limit": 5}).get("audit_logs", [])
    assert isinstance(tgs_logs, list), "加密 TGS 管理请求未返回审计列表"
    old_as = request("127.0.0.1", ports["as"], Message(type="AS_ADMIN_LIST_USERS", seq=0, body={"admin_token": token}), timeout=5.0)
    assert old_as["type"] == "ERROR" and "加密格式" in old_as["body"].get("error", ""), "AS 仍接受旧版明文管理请求"
    old_tgs = request("127.0.0.1", ports["tgs"], Message(type="TGS_ADMIN_AUDIT_QUERY", seq=0, body={"admin_token": token}), timeout=5.0)
    assert old_tgs["type"] == "ERROR" and "加密格式" in old_tgs["body"].get("error", ""), "TGS 仍接受旧版明文管理请求"
    admin.admin_mute_user("alice", duration_seconds=60, reason="e2e 禁言")
    try:
        alice.send_chat_message("这条消息应被禁言拒绝")
        raise AssertionError("alice 被禁言后仍能发送消息")
    except RuntimeError as exc:
        assert "禁言" in str(exc), f"禁言错误提示不符合预期：{exc}"
    admin.admin_unmute_user("alice")
    alice.send_chat_message("e2e 解除禁言后消息")

    kick_result = admin.admin_kick_user("bob")
    assert kick_result.get("target_username") == "bob", "踢出用户响应缺少目标用户"
    try:
        bob.poll_chat_messages()
        raise AssertionError("bob 被踢出后仍能继续轮询")
    except RuntimeError as exc:
        assert "会话已被撤销" in str(exc) or "SESSION_REVOKED" in str(exc), f"踢出后的错误提示不符合预期：{exc}"


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


def _poll_until(fetch, predicate, timeout: float = 10.0):
    deadline = time.time() + timeout
    last_value = []
    while time.time() < deadline:
        last_value = fetch()
        if predicate(last_value):
            return last_value
        time.sleep(0.25)
    return last_value


def _has_text(messages: list[dict], text: str) -> bool:
    return any(message.get("text") == text for message in messages)


def _write_tiny_png(path: Path) -> None:
    png_b64 = (
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8"
        "/x8AAwMCAO+/p9sAAAAASUVORK5CYII="
    )
    path.write_bytes(base64.b64decode(png_b64))


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


def _print_server_logs(processes: list[subprocess.Popen[str]]) -> None:
    for process in processes:
        if not process.stdout:
            continue
        try:
            output = process.stdout.read()
        except Exception:
            output = ""
        if output:
            print(output)


if __name__ == "__main__":
    raise SystemExit(main())
