"""初始化 SafeChat SQLite 数据库。"""

from __future__ import annotations

import os
import sqlite3
import time
from argparse import ArgumentParser
from pathlib import Path

from common.config.settings import database_path, service_address, service_key
from common.crypto.sha256 import sha256_hex

DB_PATH = database_path()
ROLE_DB_PATHS = {
    "as": database_path("as"),
    "tgs": database_path("tgs"),
    "chat": database_path("chat"),
}
VALID_ROLES = ("as", "tgs", "chat", "all")


SEED_USERS = (
    ("admin", "admin123", "admin"),
    ("alice", "alice123", "user"),
    ("bob", "bob123", "user"),
    ("carol", "carol123", "user"),
    ("dave", "dave123", "user"),
)


def hash_password(password: str, salt_hex: str) -> str:
    """返回 SHA-256 加盐密码哈希。"""
    salt = bytes.fromhex(salt_hex)
    return sha256_hex(salt + password.encode("utf-8"))


def create_schema(conn: sqlite3.Connection) -> None:
    """创建 SafeChat 持久化表结构。"""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            password_plain TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            public_key TEXT DEFAULT '',
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            action_type TEXT NOT NULL,
            content_enc TEXT,
            timestamp INTEGER NOT NULL,
            signature TEXT
        );

        CREATE TABLE IF NOT EXISTS ip_bans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            reason TEXT,
            ban_time INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_name TEXT UNIQUE NOT NULL,
            service_host TEXT NOT NULL,
            service_port INTEGER NOT NULL,
            service_key TEXT NOT NULL,
            public_key TEXT,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS active_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            session_id TEXT UNIQUE NOT NULL,
            client_ip TEXT NOT NULL,
            tgt_issued_at INTEGER NOT NULL,
            tgt_expires_at INTEGER NOT NULL,
            service_ticket_issued_at INTEGER,
            service_ticket_expires_at INTEGER,
            last_seen INTEGER NOT NULL,
            client_type TEXT NOT NULL DEFAULT 'client',
            status TEXT NOT NULL DEFAULT 'active',
            FOREIGN KEY (username) REFERENCES users(username)
        );
        CREATE INDEX IF NOT EXISTS idx_active_sessions_username ON active_sessions(username);
        CREATE INDEX IF NOT EXISTS idx_active_sessions_status ON active_sessions(status);

        CREATE TABLE IF NOT EXISTS offline_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT NOT NULL,
            sender TEXT NOT NULL,
            message_text TEXT NOT NULL,
            chat_type TEXT DEFAULT 'private',
            created_at INTEGER NOT NULL,
            status TEXT DEFAULT 'pending'
        );
        CREATE INDEX IF NOT EXISTS idx_offline_messages_recipient ON offline_messages(recipient);
        CREATE INDEX IF NOT EXISTS idx_offline_messages_status ON offline_messages(status);

        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT DEFAULT '',
            chat_type TEXT NOT NULL DEFAULT 'group',
            session_key TEXT NOT NULL,
            message_text TEXT NOT NULL,
            message_hmac TEXT DEFAULT '',
            message_sig TEXT DEFAULT '',
            message_pubkey TEXT DEFAULT '',
            image_data TEXT DEFAULT '',
            file_name TEXT DEFAULT '',
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_chat_messages_session ON chat_messages(session_key, id);
        CREATE INDEX IF NOT EXISTS idx_chat_messages_sender ON chat_messages(sender);
        CREATE INDEX IF NOT EXISTS idx_chat_messages_recipient ON chat_messages(recipient);

        CREATE TABLE IF NOT EXISTS mute_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_type TEXT NOT NULL,
            target_value TEXT NOT NULL,
            scope TEXT NOT NULL DEFAULT 'global',
            reason TEXT DEFAULT '',
            muted_by TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'active'
        );
        CREATE INDEX IF NOT EXISTS idx_mute_rules_target ON mute_rules(target_type, target_value, status);
        CREATE INDEX IF NOT EXISTS idx_mute_rules_expires ON mute_rules(expires_at);

        CREATE TABLE IF NOT EXISTS session_revocations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            revoked_by TEXT NOT NULL,
            reason TEXT DEFAULT '',
            revoked_at INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'active'
        );
        CREATE INDEX IF NOT EXISTS idx_session_revocations_user ON session_revocations(username, status);
        """
    )
    _ensure_users_public_key_column(conn)
    _ensure_chat_message_security_columns(conn)


def seed_auth_users(conn: sqlite3.Connection) -> None:
    """当用户不存在时为课程演示用户添加 SHA-256 加盐哈希密码。"""
    now = int(time.time() * 1000)
    for username, password, user_role in SEED_USERS:
        salt = os.urandom(32).hex()
        conn.execute(
            """
            INSERT OR IGNORE INTO users
                (username, password_hash, password_plain, salt, role, public_key, created_at)
            VALUES (?, ?, ?, ?, ?, '', ?)
            """,
            (username, hash_password(password, salt), password, salt, user_role, now),
        )


def seed_role_users(conn: sqlite3.Connection) -> None:
    """为联系人列表添加非 AS 用户角色副本（不存在时）。"""
    now = int(time.time() * 1000)
    for username, _password, user_role in SEED_USERS:
        conn.execute(
            """
            INSERT OR IGNORE INTO users
                (username, password_hash, password_plain, salt, role, public_key, created_at)
            VALUES (?, '', '', '', ?, '', ?)
            """,
            (username, user_role, now),
        )


def seed_services(conn: sqlite3.Connection, role: str = "all") -> None:
    """初始化 AS/TGS/ChatServer 逻辑服务记录。"""
    now = int(time.time() * 1000)
    tgs_host, tgs_port = service_address("tgs_server")
    chat_host, chat_port = service_address("chat_server")
    services = []
    if role in {"all", "as", "tgs"}:
        services.append(("tgs_server", tgs_host, tgs_port, service_key("tgs_server")))
    if role in {"all", "tgs", "chat"}:
        services.append(("chat_server", chat_host, chat_port, service_key("chat_server")))
    for service_name, host, port, key in services:
        conn.execute(
            """
            INSERT INTO services
                (service_name, service_host, service_port, service_key, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(service_name) DO UPDATE SET
                service_host = excluded.service_host,
                service_port = excluded.service_port,
                service_key = excluded.service_key
            """,
            (service_name, host, port, key, now),
        )


def init_database(path: Path, role: str) -> None:
    """创建并初始化一个指定角色的 SQLite 数据库。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        create_schema(conn)
        if role in {"all", "as"}:
            seed_auth_users(conn)
        elif role == "chat":
            seed_role_users(conn)
        seed_services(conn, role)
        conn.commit()
    print(f"Initialized {role} database: {path}")


def ensure_database(role: str) -> Path:
    """在不重置现有数据的前提下确保指定服务数据库就绪。"""
    if role not in ROLE_DB_PATHS:
        raise ValueError(f"unknown database role: {role}")
    path = ROLE_DB_PATHS[role]
    init_database(path, role)
    return path


def _ensure_users_public_key_column(conn: sqlite3.Connection) -> None:
    columns = [row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
    if "public_key" not in columns:
        conn.execute("ALTER TABLE users ADD COLUMN public_key TEXT DEFAULT ''")


def _ensure_chat_message_security_columns(conn: sqlite3.Connection) -> None:
    columns = [row[1] for row in conn.execute("PRAGMA table_info(chat_messages)").fetchall()]
    if "message_hmac" not in columns:
        conn.execute("ALTER TABLE chat_messages ADD COLUMN message_hmac TEXT DEFAULT ''")
    if "message_sig" not in columns:
        conn.execute("ALTER TABLE chat_messages ADD COLUMN message_sig TEXT DEFAULT ''")
    if "message_pubkey" not in columns:
        conn.execute("ALTER TABLE chat_messages ADD COLUMN message_pubkey TEXT DEFAULT ''")


def main(argv: list[str] | None = None) -> None:
    """创建各角色数据库表结构并添加初始数据。"""
    parser = ArgumentParser(description="Initialize SafeChat SQLite databases.")
    parser.add_argument(
        "--role",
        choices=VALID_ROLES,
        default="all",
        help="database role to initialize: as, tgs, chat, or all for local development",
    )
    args = parser.parse_args(argv)

    if args.role == "all":
        for role, path in ROLE_DB_PATHS.items():
            init_database(path, role)
        return

    init_database(ROLE_DB_PATHS[args.role], args.role)


if __name__ == "__main__":
    main()
