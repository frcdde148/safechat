"""Initialize the SQLite database for SafeChat."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import time
from pathlib import Path


DB_PATH = Path(__file__).resolve().parent / "chatroom.db"


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
                (username, password_hash, salt, role, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, hash_password(password, salt), salt, role, now),
        )


def seed_services(conn: sqlite3.Connection) -> None:
    """Seed logical AS/TGS/ChatServer service records."""
    now = int(time.time() * 1000)
    services = (
        ("tgs_server", "127.0.0.1", 8001, "demo-tgs-key"),
        ("chat_server", "127.0.0.1", 9000, "demo-chat-key"),
    )
    for service_name, host, port, key in services:
        conn.execute(
            """
            INSERT OR IGNORE INTO services
                (service_name, service_host, service_port, service_key, created_at)
            VALUES (?, ?, ?, ?, ?)
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
