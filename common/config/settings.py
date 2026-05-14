"""所有程序共享的配置加载工具。"""

from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SETTINGS_PATH = PROJECT_ROOT / "common" / "config" / "settings.json"


DEFAULT_SETTINGS: dict[str, Any] = {
    "as_server": {
        "bind_host": "127.0.0.1",
        "public_host": "127.0.0.1",
        "port": 8000,
    },
    "tgs_server": {
        "bind_host": "127.0.0.1",
        "public_host": "127.0.0.1",
        "port": 8001,
        "service_key": "demo-tgs-key",
    },
    "chat_server": {
        "bind_host": "127.0.0.1",
        "public_host": "127.0.0.1",
        "port": 9000,
        "service_name": "chat_server",
        "service_key": "demo-chat-key",
    },
    "database": {
        "path": "database/chatroom.db",
        "as_path": "database/as.db",
        "tgs_path": "database/tgs.db",
        "chat_path": "database/chat.db",
    },
    "logs": {
        "auth_log": "logs/auth.log",
        "chat_log": "logs/chat.log",
        "audit_log": "logs/audit.log",
    },
    "security": {
        "password_hash": "sha256",
        "signature": "rsa-1024",
        "ticket_cipher": "des",
        "audit_content_cipher": "des",
        "admin_token_secret": "safechat-admin-token-secret",
    },
    "performance": {
        "history_page_size": 80,
        "encrypt_images": False,
    },
}


def load_settings(path: Path | None = None) -> dict[str, Any]:
    """加载 settings.json，未配置时使用本地开发默认值。"""
    settings = deepcopy(DEFAULT_SETTINGS)
    if path is not None:
        config_path = path
    elif os.environ.get("SAFECHAT_SETTINGS_PATH"):
        config_path = Path(os.environ["SAFECHAT_SETTINGS_PATH"])
    else:
        config_path = SETTINGS_PATH
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as file:
            _deep_update(settings, json.load(file))
    return settings


def database_path(role: str = "default") -> Path:
    """返回指定服务角色的 SQLite 数据库路径。"""
    database = load_settings()["database"]
    key = {
        "as": "as_path",
        "tgs": "tgs_path",
        "chat": "chat_path",
    }.get(role, "path")
    raw_path = Path(database.get(key) or database["path"])
    return raw_path if raw_path.is_absolute() else PROJECT_ROOT / raw_path


def server_bind_address(section: str) -> tuple[str, int]:
    """返回服务器配置的监听主机地址和端口。"""
    config = load_settings()[section]
    return str(config["bind_host"]), int(config["port"])


def service_address(section: str) -> tuple[str, int]:
    """返回服务注册中存储的对外公告地址和端口。"""
    config = load_settings()[section]
    return str(config["public_host"]), int(config["port"])


def service_key(section: str) -> str:
    """返回配置的逻辑服务密钥。"""
    return str(load_settings()[section]["service_key"])


def _deep_update(target: dict[str, Any], override: dict[str, Any]) -> None:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_update(target[key], value)
        else:
            target[key] = value
