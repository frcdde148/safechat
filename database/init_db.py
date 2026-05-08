"""Initialize the SQLite database for SafeChat."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import time
from pathlib import Path

from common.config.settings import database_path, service_address, service_key

DB_PATH = database_path()


SEED_USERS = (
    ("alice", "alice123", "user"),
    ("bob", "bob123", "user"),
    ("carol", "carol123", "user"),
    ("dave", "dave123", "user"),
)


def hash_password(password: str, salt_hex: str) -> str:
    """Return a SHA-256 salted password hash."""
    salt = bytes.fromhex(salt_hex)
    return hashlib.sha256(salt + password.encode("utf-8")).hexdigest()


def create_schema(conn: sqlite3.Connection) -> None:
    """Create SafeChat persistence tables."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            password_plain TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT DEFAULT 'user',
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
        """
    )


def seed_users(conn: sqlite3.Connection) -> None:
    """Seed four course-demo users with salted SHA-256 hashes."""
    now = int(time.time() * 1000)
    for username, password, role in SEED_USERS:
        salt = os.urandom(32).hex()
        conn.execute(
            """
            INSERT OR IGNORE INTO users
                (username, password_hash, password_plain, salt, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (username, hash_password(password, salt), password, salt, role, now),
        )


def seed_services(conn: sqlite3.Connection) -> None:
    """Seed logical AS/TGS/ChatServer service records."""
    now = int(time.time() * 1000)
    tgs_host, tgs_port = service_address("tgs_server")
    chat_host, chat_port = service_address("chat_server")
    services = (
        ("tgs_server", tgs_host, tgs_port, service_key("tgs_server")),
        ("chat_server", chat_host, chat_port, service_key("chat_server")),
    )
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


def main() -> None:
    """Create tables and seed initial data."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        create_schema(conn)
        seed_users(conn)
        seed_services(conn)
        conn.commit()
    print(f"Initialized database: {DB_PATH}")


if __name__ == "__main__":
    main()
