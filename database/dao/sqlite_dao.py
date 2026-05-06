"""SQLite access helpers."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any

from common.config.settings import database_path
from common.crypto.sha256 import verify_password


class SQLiteDAO:
    """Small DAO wrapper used by the demo authentication servers."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or database_path()

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

    def get_active_session(self, username: str) -> dict[str, Any] | None:
        """Get the active session for a user if exists."""
        now = int(time.time() * 1000)
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM active_sessions
                WHERE username = ? AND status = 'active' AND tgt_expires_at >= ?
                LIMIT 1
                """,
                (username, now),
            ).fetchone()
            return dict(row) if row else None

    def create_session(
        self,
        username: str,
        session_id: str,
        client_ip: str,
        tgt_issued_at: int,
        tgt_expires_at: int,
    ) -> None:
        """Create a new session, invalidating any existing sessions for the user."""
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE active_sessions
                SET status = 'invalidated'
                WHERE username = ? AND status = 'active'
                """,
                (username,),
            )
            conn.execute(
                """
                INSERT INTO active_sessions
                    (username, session_id, client_ip, tgt_issued_at, tgt_expires_at, last_seen, status)
                VALUES (?, ?, ?, ?, ?, ?, 'active')
                """,
                (username, session_id, client_ip, tgt_issued_at, tgt_expires_at, int(time.time() * 1000)),
            )
            conn.commit()

    def update_session_service_ticket(
        self,
        session_id: str,
        service_ticket_issued_at: int,
        service_ticket_expires_at: int,
    ) -> None:
        """Update session with service ticket info."""
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE active_sessions
                SET service_ticket_issued_at = ?, service_ticket_expires_at = ?, last_seen = ?
                WHERE session_id = ?
                """,
                (service_ticket_issued_at, service_ticket_expires_at, int(time.time() * 1000), session_id),
            )
            conn.commit()

    def update_session_last_seen(self, session_id: str) -> None:
        """Update last seen timestamp for a session."""
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE active_sessions
                SET last_seen = ?
                WHERE session_id = ?
                """,
                (int(time.time() * 1000), session_id),
            )
            conn.commit()

    def invalidate_session(self, session_id: str) -> None:
        """Invalidate a session by session_id."""
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE active_sessions
                SET status = 'invalidated'
                WHERE session_id = ?
                """,
                (session_id,),
            )
            conn.commit()

    def invalidate_user_sessions(self, username: str) -> None:
        """Invalidate all sessions for a user."""
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE active_sessions
                SET status = 'invalidated'
                WHERE username = ?
                """,
                (username,),
            )
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
