"""SQLite access helpers."""

from __future__ import annotations

import sqlite3
import time
import ipaddress
from pathlib import Path
from typing import Any

from common.config.settings import database_path
from common.crypto.sha256 import new_salt_hex, salted_password_hash, verify_password


class SQLiteDAO:
    """Small DAO wrapper used by the demo authentication servers."""

    def __init__(self, db_path: Path | None = None, role: str = "default") -> None:
        self.db_path = db_path or database_path(role)

    def get_user(self, username: str) -> dict[str, Any] | None:
        """Fetch one user by username."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            return dict(row) if row else None

    def list_users(self) -> list[dict[str, Any]]:
        """Return all known users for contact-list display."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT username, role
                FROM users
                ORDER BY username ASC
                """
            ).fetchall()
            return [dict(row) for row in rows]

    def add_mute_rule(
        self,
        target_type: str,
        target_value: str,
        muted_by: str,
        expires_at: int,
        reason: str = "",
        scope: str = "global",
    ) -> int:
        """Create or replace an active mute rule for one user or IP."""
        now = int(time.time() * 1000)
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE mute_rules
                SET status = 'revoked'
                WHERE target_type = ? AND target_value = ? AND scope = ? AND status = 'active'
                """,
                (target_type, target_value, scope),
            )
            cursor = conn.execute(
                """
                INSERT INTO mute_rules
                    (target_type, target_value, scope, reason, muted_by, created_at, expires_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
                """,
                (target_type, target_value, scope, reason, muted_by, now, expires_at),
            )
            conn.commit()
            return int(cursor.lastrowid)

    def revoke_mute_rule(self, target_type: str, target_value: str, scope: str = "global") -> int:
        """Revoke active mute rules for one target and return affected row count."""
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE mute_rules
                SET status = 'revoked'
                WHERE target_type = ? AND target_value = ? AND scope = ? AND status = 'active'
                """,
                (target_type, target_value, scope),
            )
            conn.commit()
            return int(cursor.rowcount)

    def get_active_mute(self, target_type: str, target_value: str, scope: str = "global") -> dict[str, Any] | None:
        """Return an active, unexpired mute rule for one target."""
        now = int(time.time() * 1000)
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM mute_rules
                WHERE target_type = ?
                  AND target_value = ?
                  AND scope = ?
                  AND status = 'active'
                  AND expires_at > ?
                ORDER BY expires_at DESC
                LIMIT 1
                """,
                (target_type, target_value, scope, now),
            ).fetchone()
            return dict(row) if row else None

    def add_session_revocation(self, username: str, revoked_by: str, reason: str = "") -> int:
        """Mark a user's current ChatServer session state as revoked."""
        now = int(time.time() * 1000)
        with self._connect() as conn:
            self._ensure_session_revocations_table(conn)
            conn.execute(
                """
                UPDATE session_revocations
                SET status = 'cleared'
                WHERE username = ? AND status = 'active'
                """,
                (username,),
            )
            cursor = conn.execute(
                """
                INSERT INTO session_revocations (username, revoked_by, reason, revoked_at, status)
                VALUES (?, ?, ?, ?, 'active')
                """,
                (username, revoked_by, reason, now),
            )
            conn.commit()
            return int(cursor.lastrowid)

    def get_active_session_revocation(self, username: str) -> dict[str, Any] | None:
        """Return the active session revocation for a user, if any."""
        with self._connect() as conn:
            self._ensure_session_revocations_table(conn)
            row = conn.execute(
                """
                SELECT * FROM session_revocations
                WHERE username = ? AND status = 'active'
                ORDER BY revoked_at DESC
                LIMIT 1
                """,
                (username,),
            ).fetchone()
            return dict(row) if row else None

    def clear_session_revocations(self, username: str) -> int:
        """Clear active revocations after a fresh Kerberos service login."""
        with self._connect() as conn:
            self._ensure_session_revocations_table(conn)
            cursor = conn.execute(
                """
                UPDATE session_revocations
                SET status = 'cleared'
                WHERE username = ? AND status = 'active'
                """,
                (username,),
            )
            conn.commit()
            return int(cursor.rowcount)

    def verify_user_password(self, username: str, password: str) -> bool:
        """Return whether username/password matches the stored salted hash."""
        user = self.get_user(username)
        if not user:
            return False
        return verify_password(password, user["salt"], user["password_hash"])

    def create_user(self, username: str, password: str, role: str = "user") -> None:
        """Create one user with a salted password hash."""
        now = int(time.time() * 1000)
        salt = new_salt_hex()
        password_hash = salted_password_hash(password, salt)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, password_plain, salt, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (username, password_hash, password, salt, role, now),
            )
            conn.commit()

    def update_user_password(self, username: str, password: str) -> bool:
        """Replace one user's password hash and return whether a row changed."""
        salt = new_salt_hex()
        password_hash = salted_password_hash(password, salt)
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE users
                SET password_hash = ?, password_plain = ?, salt = ?
                WHERE username = ?
                """,
                (password_hash, password, salt, username),
            )
            conn.commit()
            return int(cursor.rowcount) > 0

    def count_admin_users(self) -> int:
        """Return number of users with admin role."""
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS total FROM users WHERE role = 'admin'").fetchone()
            return int(row["total"] if row else 0)

    def delete_user(self, username: str) -> bool:
        """Delete a user account while preserving audit and chat history."""
        with self._connect() as conn:
            self._ensure_session_revocations_table(conn)
            cursor = conn.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.execute("UPDATE active_sessions SET status = 'invalidated' WHERE username = ?", (username,))
            conn.commit()
            return int(cursor.rowcount) > 0

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
        now = int(time.time() * 1000)
        target_ip = self._normalize_ip(ip_address)
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM ip_bans
                """,
            ).fetchall()
            for row in rows:
                if self._normalize_ip(row["ip_address"]) != target_ip:
                    continue
                created_at = int(row["created_at"])
                if created_at < 10_000_000_000:
                    created_at *= 1000
                ban_time_ms = int(row["ban_time"]) * 1000
                if created_at + ban_time_ms >= now:
                    return True
            return False

    def get_active_session(self, username: str, client_type: str = "client") -> dict[str, Any] | None:
        """Get the active session for a user and client type if exists."""
        now = int(time.time() * 1000)
        with self._connect() as conn:
            self._ensure_active_sessions_client_type(conn)
            row = conn.execute(
                """
                SELECT * FROM active_sessions
                WHERE username = ?
                  AND status = 'active'
                  AND tgt_expires_at >= ?
                  AND COALESCE(client_type, 'client') = ?
                LIMIT 1
                """,
                (username, now, client_type),
            ).fetchone()
            return dict(row) if row else None

    def create_session(
        self,
        username: str,
        session_id: str,
        client_ip: str,
        tgt_issued_at: int,
        tgt_expires_at: int,
        invalidate_existing: bool = True,
        client_type: str = "client",
    ) -> None:
        """Create a new session, invalidating any existing sessions for the user."""
        with self._connect() as conn:
            self._ensure_active_sessions_client_type(conn)
            if invalidate_existing:
                conn.execute(
                    """
                    UPDATE active_sessions
                    SET status = 'invalidated'
                    WHERE username = ? AND status = 'active' AND COALESCE(client_type, 'client') = ?
                    """,
                    (username, client_type),
                )
            conn.execute(
                """
                INSERT INTO active_sessions
                    (username, session_id, client_ip, tgt_issued_at, tgt_expires_at, last_seen, client_type, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
                """,
                (username, session_id, client_ip, tgt_issued_at, tgt_expires_at, int(time.time() * 1000), client_type),
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
                WHERE session_id = ? AND status = 'active'
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

    def store_offline_message(self, recipient: str, sender: str, plaintext: str) -> None:
        """Store a message for an offline user."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO offline_messages
                    (recipient, sender, message_text, chat_type, created_at, status)
                VALUES (?, ?, ?, 'private', ?, 'pending')
                """,
                (recipient, sender, plaintext, int(time.time() * 1000)),
            )
            conn.commit()

    def get_offline_messages(self, recipient: str) -> list[dict[str, Any]]:
        """Get all pending offline messages for a user, ordered by creation time."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM offline_messages
                WHERE recipient = ? AND status = 'pending'
                ORDER BY created_at ASC
                """,
                (recipient,),
            ).fetchall()
            return [dict(row) for row in rows]

    def delete_offline_message(self, message_id: int) -> None:
        """Delete a specific offline message."""
        with self._connect() as conn:
            conn.execute(
                """
                DELETE FROM offline_messages
                WHERE id = ?
                """,
                (message_id,),
            )
            conn.commit()

    def clear_offline_messages(self, recipient: str) -> None:
        """Clear all offline messages for a user."""
        with self._connect() as conn:
            conn.execute(
                """
                DELETE FROM offline_messages
                WHERE recipient = ?
                """,
                (recipient,),
            )
            conn.commit()

    def store_chat_message(
        self,
        sender: str,
        recipient: str,
        chat_type: str,
        session_key: str,
        message_text: str,
        image_data: str = "",
        file_name: str = "",
    ) -> int:
        """Persist one traceable chat message and return its database id."""
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO chat_messages
                    (sender, recipient, chat_type, session_key, message_text, image_data, file_name, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sender,
                    recipient,
                    chat_type,
                    session_key,
                    message_text,
                    image_data,
                    file_name,
                    int(time.time() * 1000),
                ),
            )
            conn.commit()
            return int(cursor.lastrowid)

    def list_chat_messages(self, session_key: str, after_id: int, username: str) -> list[dict[str, Any]]:
        """List persisted messages in a session that the user is allowed to read."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM chat_messages
                WHERE session_key = ?
                  AND id > ?
                  AND (
                    chat_type != 'private'
                    OR sender = ?
                    OR recipient = ?
                  )
                ORDER BY id ASC
                """,
                (session_key, after_id, username, username),
            ).fetchall()
            return [dict(row) for row in rows]

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _normalize_ip(ip_address: str) -> str:
        text = str(ip_address or "").strip()
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            return text
        if getattr(ip, "ipv4_mapped", None):
            return str(ip.ipv4_mapped)
        return str(ip)

    @staticmethod
    def _ensure_session_revocations_table(conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS session_revocations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                revoked_by TEXT NOT NULL,
                reason TEXT DEFAULT '',
                revoked_at INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'active'
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_session_revocations_user
            ON session_revocations(username, status)
            """
        )

    @staticmethod
    def _ensure_active_sessions_client_type(conn: sqlite3.Connection) -> None:
        columns = [row["name"] for row in conn.execute("PRAGMA table_info(active_sessions)").fetchall()]
        if "client_type" not in columns:
            conn.execute("ALTER TABLE active_sessions ADD COLUMN client_type TEXT NOT NULL DEFAULT 'client'")
