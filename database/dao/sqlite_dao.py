"""SQLite access helpers."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any

from common.crypto.sha256 import verify_password
from database.init_db import DB_PATH


class SQLiteDAO:
    """Small DAO wrapper used by the demo authentication servers."""

    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = db_path

    def get_user(self, username: str) -> dict[str, Any] | None:
        """Fetch one user by username."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            return dict(row) if row else None

    def verify_user_password(self, username: str, password: str) -> bool:
        """Return whether username/password matches the stored salted hash."""
        user = self.get_user(username)
        if not user:
            return False
        return verify_password(password, user["salt"], user["password_hash"])

    def get_service(self, service_name: str) -> dict[str, Any] | None:
        """Fetch one service record by logical service name."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM services WHERE service_name = ?", (service_name,)).fetchone()
            return dict(row) if row else None

    def add_audit_log(
        self,
        session_id: str,
        user_id: str,
        client_ip: str,
        action_type: str,
        content_enc: str = "",
        signature: str = "",
    ) -> None:
        """Persist an audit event."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs
                    (session_id, user_id, client_ip, action_type, content_enc, timestamp, signature)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (session_id, user_id, client_ip, action_type, content_enc, int(time.time() * 1000), signature),
            )
            conn.commit()

    def is_ip_banned(self, ip_address: str) -> bool:
        """Return whether an IP currently has an active ban."""
        now = int(time.time())
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM ip_bans
                WHERE ip_address = ? AND created_at + ban_time >= ?
                """,
                (ip_address, now),
            ).fetchone()
            return row is not None

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
