"""Configuration helpers shared by all programs."""

from __future__ import annotations

import json
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
}


def load_settings(path: Path | None = None) -> dict[str, Any]:
    """Load settings.json with safe defaults for local development."""
    settings = deepcopy(DEFAULT_SETTINGS)
    config_path = path or SETTINGS_PATH
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as file:
            _deep_update(settings, json.load(file))
    return settings


def database_path(role: str = "default") -> Path:
    """Return the configured SQLite database path for a service role."""
    database = load_settings()["database"]
    key = {
        "as": "as_path",
        "tgs": "tgs_path",
        "chat": "chat_path",
    }.get(role, "path")
    raw_path = Path(database.get(key) or database["path"])
    return raw_path if raw_path.is_absolute() else PROJECT_ROOT / raw_path


def server_bind_address(section: str) -> tuple[str, int]:
    """Return the configured bind host/port for a server section."""
    config = load_settings()[section]
    return str(config["bind_host"]), int(config["port"])


def service_address(section: str) -> tuple[str, int]:
    """Return the advertised service host/port stored in the service registry."""
    config = load_settings()[section]
    return str(config["public_host"]), int(config["port"])


def service_key(section: str) -> str:
    """Return a configured logical service key."""
    return str(load_settings()[section]["service_key"])


def _deep_update(target: dict[str, Any], override: dict[str, Any]) -> None:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _deep_update(target[key], value)
        else:
            target[key] = value
