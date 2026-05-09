"""PyQt admin console for SafeChat operations and audit review."""

from __future__ import annotations

import csv
import sqlite3
import time
from pathlib import Path
from typing import Any

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QComboBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from client.net.auth_client import AuthClient
from common.config.settings import database_path, load_settings, service_address
from common.protocol.message import Message
from common.protocol.socket_io import request


AUTH_FLOW = ("C_AS_REQ", "AS_C_REP", "C_TGS_REQ", "TGS_C_REP", "C_V_REQ", "V_C_REP")


class AdminConsole(QMainWindow):
    """Standalone management console for users, sessions, audits, and chat moderation."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SafeChat Admin Console")
        self.resize(1500, 930)
        self._settings = load_settings()
        self._auth_client: AuthClient | None = None
        self._contacts: list[dict[str, Any]] = []

        root = QWidget()
        layout = QVBoxLayout(root)
        layout.addWidget(self._build_login_panel())

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_overview_tab(), "Online / Mute")
        self.tabs.addTab(self._build_user_admin_tab(), "Users / Roles")
        self.tabs.addTab(self._build_sessions_tab(), "Tickets / Sessions")
        self.tabs.addTab(self._build_ip_ban_tab(), "IP Bans")
        self.tabs.addTab(self._build_chat_records_tab(), "Chat Records")
        self.tabs.addTab(self._build_audit_tab(), "Audit Logs")
        self.tabs.addTab(self._build_status_tab(), "Service Status")
        layout.addWidget(self.tabs, 1)

        self.setCentralWidget(root)
        self._set_admin_actions_enabled(False)
        self.refresh_status()
        self.refresh_user_roles()
        self.refresh_sessions()
        self.refresh_ip_bans()

    def _build_login_panel(self) -> QGroupBox:
        group = QGroupBox("Admin Kerberos Authentication")
        layout = QGridLayout(group)
        as_host, as_port = service_address("as_server")
        self.username_input = QLineEdit("admin")
        self.password_input = QLineEdit("admin123")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.as_host_input = QLineEdit(as_host)
        self.as_port_input = QSpinBox()
        self.as_port_input.setRange(1, 65535)
        self.as_port_input.setValue(as_port)
        self.login_button = QPushButton("Authenticate")
        self.login_button.clicked.connect(self.login_admin)
        self.login_status = QLabel("Not authenticated")

        layout.addWidget(QLabel("Username"), 0, 0)
        layout.addWidget(self.username_input, 0, 1)
        layout.addWidget(QLabel("Password"), 0, 2)
        layout.addWidget(self.password_input, 0, 3)
        layout.addWidget(QLabel("AS Host"), 1, 0)
        layout.addWidget(self.as_host_input, 1, 1)
        layout.addWidget(QLabel("AS Port"), 1, 2)
        layout.addWidget(self.as_port_input, 1, 3)
        layout.addWidget(self.login_button, 0, 4, 2, 1)
        layout.addWidget(self.login_status, 0, 5, 2, 1)
        return group

    def _build_overview_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        actions = QHBoxLayout()
        self.refresh_users_button = QPushButton("Refresh Contacts")
        self.refresh_users_button.clicked.connect(self.refresh_users)
        self.mute_button = QPushButton("Mute Selected")
        self.mute_button.clicked.connect(self.mute_selected_user)
        self.unmute_button = QPushButton("Unmute Selected")
        self.unmute_button.clicked.connect(self.unmute_selected_user)
        self.kick_button = QPushButton("Kick Selected Online User")
        self.kick_button.clicked.connect(self.kick_selected_user)
        self.duration_input = QSpinBox()
        self.duration_input.setRange(1, 1440)
        self.duration_input.setValue(10)
        self.reason_input = QLineEdit("Muted by admin console")
        actions.addWidget(self.refresh_users_button)
        actions.addWidget(QLabel("Mute minutes"))
        actions.addWidget(self.duration_input)
        actions.addWidget(QLabel("Reason"))
        actions.addWidget(self.reason_input, 1)
        actions.addWidget(self.mute_button)
        actions.addWidget(self.unmute_button)
        actions.addWidget(self.kick_button)
        layout.addLayout(actions)

        self.users_table = QTableWidget(0, 8)
        self.users_table.setHorizontalHeaderLabels(
            ["User", "Role", "Status", "IP", "Last Seen", "Muted", "Muted Until", "Session"]
        )
        self._stretch_table(self.users_table)
        layout.addWidget(self.users_table, 1)
        return tab

    def _build_user_admin_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        actions = QHBoxLayout()
        self.refresh_roles_button = QPushButton("Refresh Users")
        self.refresh_roles_button.clicked.connect(self.refresh_user_roles)
        self.role_selector = QComboBox()
        self.role_selector.addItems(["user", "admin"])
        self.apply_role_button = QPushButton("Set Selected Role")
        self.apply_role_button.clicked.connect(self.set_selected_user_role)
        actions.addWidget(self.refresh_roles_button)
        actions.addWidget(QLabel("Role"))
        actions.addWidget(self.role_selector)
        actions.addWidget(self.apply_role_button)
        actions.addStretch(1)
        layout.addLayout(actions)

        self.roles_table = QTableWidget(0, 5)
        self.roles_table.setHorizontalHeaderLabels(["User", "AS Role", "Chat Role", "AS Created", "Chat Created"])
        self._stretch_table(self.roles_table)
        layout.addWidget(self.roles_table, 1)
        return tab

    def _build_sessions_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        actions = QHBoxLayout()
        self.refresh_sessions_button = QPushButton("Refresh Sessions")
        self.refresh_sessions_button.clicked.connect(self.refresh_sessions)
        self.invalidate_session_button = QPushButton("Invalidate Selected User Sessions")
        self.invalidate_session_button.clicked.connect(self.invalidate_selected_sessions)
        self.kick_session_button = QPushButton("Kick Selected User Online")
        self.kick_session_button.clicked.connect(self.kick_selected_session_user)
        actions.addWidget(self.refresh_sessions_button)
        actions.addWidget(self.invalidate_session_button)
        actions.addWidget(self.kick_session_button)
        actions.addStretch(1)
        layout.addLayout(actions)

        self.sessions_table = QTableWidget(0, 9)
        self.sessions_table.setHorizontalHeaderLabels(
            ["User", "Session", "IP", "TGT Issued", "TGT Expires", "Service Issued", "Service Expires", "Last Seen", "Status"]
        )
        self._stretch_table(self.sessions_table)
        layout.addWidget(self.sessions_table, 1)
        return tab

    def _build_ip_ban_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        actions = QHBoxLayout()
        self.ban_ip_input = QLineEdit()
        self.ban_ip_input.setPlaceholderText("IP address")
        self.ban_minutes_input = QSpinBox()
        self.ban_minutes_input.setRange(1, 1440)
        self.ban_minutes_input.setValue(30)
        self.ban_reason_input = QLineEdit("Banned by admin console")
        self.add_ip_ban_button = QPushButton("Ban IP")
        self.add_ip_ban_button.clicked.connect(self.add_ip_ban)
        self.refresh_ip_bans_button = QPushButton("Refresh IP Bans")
        self.refresh_ip_bans_button.clicked.connect(self.refresh_ip_bans)
        actions.addWidget(QLabel("IP"))
        actions.addWidget(self.ban_ip_input)
        actions.addWidget(QLabel("Minutes"))
        actions.addWidget(self.ban_minutes_input)
        actions.addWidget(QLabel("Reason"))
        actions.addWidget(self.ban_reason_input, 1)
        actions.addWidget(self.add_ip_ban_button)
        actions.addWidget(self.refresh_ip_bans_button)
        layout.addLayout(actions)

        self.ip_bans_table = QTableWidget(0, 6)
        self.ip_bans_table.setHorizontalHeaderLabels(["ID", "IP", "Reason", "Created", "Expires", "Active"])
        self._stretch_table(self.ip_bans_table)
        layout.addWidget(self.ip_bans_table, 1)
        return tab

    def _build_chat_records_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        filters = QHBoxLayout()
        self.chat_type_filter = QComboBox()
        self.chat_type_filter.addItems(["All", "group", "private"])
        self.chat_user_filter = QLineEdit()
        self.chat_user_filter.setPlaceholderText("sender/recipient filter")
        self.refresh_chat_button = QPushButton("Query Chat Records")
        self.refresh_chat_button.clicked.connect(self.refresh_chat_records)
        filters.addWidget(QLabel("Type"))
        filters.addWidget(self.chat_type_filter)
        filters.addWidget(QLabel("User"))
        filters.addWidget(self.chat_user_filter, 1)
        filters.addWidget(self.refresh_chat_button)
        layout.addLayout(filters)

        self.chat_table = QTableWidget(0, 8)
        self.chat_table.setHorizontalHeaderLabels(["ID", "Time", "Type", "Session", "Sender", "Recipient", "Content", "File"])
        self._stretch_table(self.chat_table)
        layout.addWidget(self.chat_table, 1)
        return tab

    def _build_audit_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        filters = QHBoxLayout()
        self.audit_db_filter = QComboBox()
        self.audit_db_filter.addItems(["as", "tgs", "chat"])
        self.audit_action_filter = QLineEdit()
        self.audit_action_filter.setPlaceholderText("action_type filter")
        self.refresh_audit_button = QPushButton("Query Audit Logs")
        self.refresh_audit_button.clicked.connect(self.refresh_audit_logs)
        self.export_audit_button = QPushButton("Export CSV")
        self.export_audit_button.clicked.connect(self.export_audit_csv)
        filters.addWidget(QLabel("DB"))
        filters.addWidget(self.audit_db_filter)
        filters.addWidget(QLabel("Action"))
        filters.addWidget(self.audit_action_filter, 1)
        filters.addWidget(self.refresh_audit_button)
        filters.addWidget(self.export_audit_button)
        layout.addLayout(filters)

        self.audit_table = QTableWidget(0, 7)
        self.audit_table.setHorizontalHeaderLabels(["ID", "Time", "User", "IP", "Action", "Content", "Signature"])
        self._stretch_table(self.audit_table)
        layout.addWidget(self.audit_table, 1)
        return tab

    def _build_status_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.refresh_status_button = QPushButton("Refresh Service Status")
        self.refresh_status_button.clicked.connect(self.refresh_status)
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        layout.addWidget(self.refresh_status_button)
        layout.addWidget(self.status_text, 1)
        return tab

    def login_admin(self) -> None:
        payload = {
            "username": self.username_input.text().strip(),
            "password": self.password_input.text(),
            "as": (self.as_host_input.text().strip(), int(self.as_port_input.value())),
        }
        if not payload["username"] or not payload["password"]:
            QMessageBox.warning(self, "Authentication Failed", "Enter admin username and password.")
            return
        self.login_button.setEnabled(False)
        try:
            client = AuthClient(payload)
            for stage in AUTH_FLOW:
                ok, detail = client.run_stage(stage)
                if not ok:
                    raise RuntimeError(detail)
            self._auth_client = client
            self.login_status.setText(f"Authenticated: {client.username}")
            self._set_admin_actions_enabled(True)
            self.refresh_all()
        except Exception as exc:
            self._auth_client = None
            self.login_status.setText("Authentication failed")
            self._set_admin_actions_enabled(False)
            QMessageBox.critical(self, "Authentication Failed", str(exc))
        finally:
            self.login_button.setEnabled(True)

    def refresh_all(self) -> None:
        self.refresh_users()
        self.refresh_user_roles()
        self.refresh_sessions()
        self.refresh_ip_bans()
        self.refresh_chat_records()
        self.refresh_audit_logs()
        self.refresh_status()

    def refresh_users(self) -> None:
        if not self._auth_client:
            return
        try:
            self._contacts = self._auth_client.fetch_online_users()
        except Exception as exc:
            QMessageBox.critical(self, "Refresh Failed", str(exc))
            return
        self.users_table.setRowCount(0)
        for user in self._contacts:
            row = self.users_table.rowCount()
            self.users_table.insertRow(row)
            self._set_row(
                self.users_table,
                row,
                [
                    user.get("username", ""),
                    user.get("role", "user"),
                    user.get("status", ""),
                    user.get("client_ip", ""),
                    self._format_ts(user.get("last_seen", 0)),
                    "yes" if user.get("muted") else "no",
                    self._format_ts(user.get("muted_until", 0)),
                    user.get("session_id", ""),
                ],
            )

    def mute_selected_user(self) -> None:
        username = self._selected_username(self.users_table)
        if not username or not self._auth_client:
            return
        try:
            self._auth_client.admin_mute_user(
                username,
                duration_seconds=int(self.duration_input.value()) * 60,
                reason=self.reason_input.text().strip() or "admin mute",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Mute Failed", str(exc))
            return
        self.refresh_users()
        self.refresh_audit_logs()

    def unmute_selected_user(self) -> None:
        username = self._selected_username(self.users_table)
        if not username or not self._auth_client:
            return
        try:
            self._auth_client.admin_unmute_user(username)
        except Exception as exc:
            QMessageBox.critical(self, "Unmute Failed", str(exc))
            return
        self.refresh_users()
        self.refresh_audit_logs()

    def kick_selected_user(self) -> None:
        username = self._selected_username(self.users_table)
        self._kick_user(username)

    def refresh_user_roles(self) -> None:
        as_users = {row["username"]: row for row in self._query_db(database_path("as"), "SELECT username, role, created_at FROM users", [])}
        chat_users = {row["username"]: row for row in self._query_db(database_path("chat"), "SELECT username, role, created_at FROM users", [])}
        names = sorted(set(as_users) | set(chat_users))
        self.roles_table.setRowCount(0)
        for username in names:
            row = self.roles_table.rowCount()
            self.roles_table.insertRow(row)
            self._set_row(
                self.roles_table,
                row,
                [
                    username,
                    as_users.get(username, {}).get("role", ""),
                    chat_users.get(username, {}).get("role", ""),
                    self._format_ts(as_users.get(username, {}).get("created_at", 0)),
                    self._format_ts(chat_users.get(username, {}).get("created_at", 0)),
                ],
            )

    def set_selected_user_role(self) -> None:
        username = self._selected_username(self.roles_table, allow_self=True)
        if not username:
            return
        role = self.role_selector.currentText()
        for db_role in ("as", "chat"):
            self._execute_db(
                database_path(db_role),
                "UPDATE users SET role = ? WHERE username = ?",
                [role, username],
            )
        self.refresh_user_roles()
        self.refresh_users()
        QMessageBox.information(self, "Role Updated", f"{username} is now {role}.")

    def refresh_sessions(self) -> None:
        rows = self._query_db(
            database_path("as"),
            """
            SELECT username, session_id, client_ip, tgt_issued_at, tgt_expires_at,
                   service_ticket_issued_at, service_ticket_expires_at, last_seen, status
            FROM active_sessions
            ORDER BY id DESC
            LIMIT 300
            """,
            [],
        )
        self.sessions_table.setRowCount(0)
        for item in rows:
            row = self.sessions_table.rowCount()
            self.sessions_table.insertRow(row)
            self._set_row(
                self.sessions_table,
                row,
                [
                    item["username"],
                    item["session_id"],
                    item["client_ip"],
                    self._format_ts(item["tgt_issued_at"]),
                    self._format_ts(item["tgt_expires_at"]),
                    self._format_ts(item["service_ticket_issued_at"]),
                    self._format_ts(item["service_ticket_expires_at"]),
                    self._format_ts(item["last_seen"]),
                    item["status"],
                ],
            )

    def invalidate_selected_sessions(self) -> None:
        username = self._selected_username(self.sessions_table, allow_self=True)
        if not username:
            return
        self._execute_db(
            database_path("as"),
            "UPDATE active_sessions SET status = 'invalidated' WHERE username = ? AND status = 'active'",
            [username],
        )
        self._kick_user(username, show_errors=False)
        self.refresh_sessions()
        self.refresh_users()
        QMessageBox.information(self, "Session Invalidated", f"Active sessions for {username} were invalidated.")

    def kick_selected_session_user(self) -> None:
        username = self._selected_username(self.sessions_table, allow_self=True)
        self._kick_user(username)

    def add_ip_ban(self) -> None:
        ip = self.ban_ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Missing IP", "Enter an IP address.")
            return
        ban_seconds = int(self.ban_minutes_input.value()) * 60
        self._execute_db(
            database_path("as"),
            """
            INSERT INTO ip_bans (ip_address, reason, ban_time, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                reason = excluded.reason,
                ban_time = excluded.ban_time,
                created_at = excluded.created_at
            """,
            [ip, self.ban_reason_input.text().strip(), ban_seconds, int(time.time())],
        )
        self.refresh_ip_bans()

    def refresh_ip_bans(self) -> None:
        rows = self._query_db(
            database_path("as"),
            "SELECT id, ip_address, reason, ban_time, created_at FROM ip_bans ORDER BY id DESC LIMIT 200",
            [],
        )
        now = int(time.time())
        self.ip_bans_table.setRowCount(0)
        for item in rows:
            expires = int(item["created_at"]) + int(item["ban_time"])
            row = self.ip_bans_table.rowCount()
            self.ip_bans_table.insertRow(row)
            self._set_row(
                self.ip_bans_table,
                row,
                [
                    item["id"],
                    item["ip_address"],
                    item["reason"],
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(item["created_at"]))),
                    time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(expires)),
                    "yes" if expires >= now else "no",
                ],
            )

    def refresh_chat_records(self) -> None:
        query = """
            SELECT id, created_at, chat_type, session_key, sender, recipient,
                   message_text, file_name
            FROM chat_messages
        """
        clauses: list[str] = []
        params: list[Any] = []
        chat_type = self.chat_type_filter.currentText()
        if chat_type != "All":
            clauses.append("chat_type = ?")
            params.append(chat_type)
        user_filter = self.chat_user_filter.text().strip()
        if user_filter:
            clauses.append("(sender LIKE ? OR recipient LIKE ?)")
            params.extend([f"%{user_filter}%", f"%{user_filter}%"])
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY id DESC LIMIT 200"
        rows = self._query_db(database_path("chat"), query, params)
        self.chat_table.setRowCount(0)
        for item in rows:
            row = self.chat_table.rowCount()
            self.chat_table.insertRow(row)
            self._set_row(
                self.chat_table,
                row,
                [
                    item["id"],
                    self._format_ts(item["created_at"]),
                    item["chat_type"],
                    item["session_key"],
                    item["sender"],
                    item["recipient"],
                    self._short_text(item["message_text"], 120),
                    item["file_name"],
                ],
            )

    def refresh_audit_logs(self) -> None:
        rows = self._audit_rows(limit=300)
        self.audit_table.setRowCount(0)
        for item in rows:
            row = self.audit_table.rowCount()
            self.audit_table.insertRow(row)
            self._set_row(
                self.audit_table,
                row,
                [
                    item["id"],
                    self._format_ts(item["timestamp"]),
                    item["user_id"],
                    item["client_ip"],
                    item["action_type"],
                    self._short_text(item["content_enc"], 160),
                    self._short_text(item["signature"], 60),
                ],
            )

    def export_audit_csv(self) -> None:
        target, _ = QFileDialog.getSaveFileName(self, "Export Audit CSV", "safechat_audit.csv", "CSV Files (*.csv)")
        if not target:
            return
        rows = self._audit_rows(limit=5000)
        with open(target, "w", newline="", encoding="utf-8-sig") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=["id", "timestamp", "time_text", "user_id", "client_ip", "action_type", "content_enc", "signature"],
            )
            writer.writeheader()
            for row in rows:
                row = dict(row)
                row["time_text"] = self._format_ts(row.get("timestamp", 0))
                writer.writerow(row)
        QMessageBox.information(self, "Export Complete", target)

    def refresh_status(self) -> None:
        lines = ["SafeChat Admin Console Status", ""]
        for section in ("as_server", "tgs_server", "chat_server"):
            host, port = service_address(section)
            lines.append(f"{section}: {host}:{port}    {'online' if self._tcp_check(host, port) else 'unreachable'}")
        lines.append("")
        for role in ("as", "tgs", "chat"):
            path = database_path(role)
            lines.append(f"{role}.db: {path}    {'exists' if path.exists() else 'missing'}")
        lines.append("")
        lines.append("Admin APIs: mute, unmute, kick are enforced by ChatServer.")
        lines.append("DB tools: roles, AS sessions, IP bans, chat records, and audit exports use configured SQLite paths.")
        self.status_text.setPlainText("\n".join(lines))

    def _audit_rows(self, limit: int) -> list[dict[str, Any]]:
        role = self.audit_db_filter.currentText()
        query = "SELECT id, timestamp, user_id, client_ip, action_type, content_enc, signature FROM audit_logs"
        params: list[Any] = []
        action_filter = self.audit_action_filter.text().strip()
        if action_filter:
            query += " WHERE action_type LIKE ?"
            params.append(f"%{action_filter}%")
        query += f" ORDER BY id DESC LIMIT {int(limit)}"
        return self._query_db(database_path(role), query, params)

    def _kick_user(self, username: str, show_errors: bool = True) -> None:
        if not username or not self._auth_client:
            return
        try:
            self._auth_client.admin_kick_user(username)
        except Exception as exc:
            if show_errors:
                QMessageBox.critical(self, "Kick Failed", str(exc))
            return
        self.refresh_users()
        self.refresh_audit_logs()

    def _selected_username(self, table: QTableWidget, allow_self: bool = False) -> str:
        selected = table.selectedItems()
        if not selected:
            QMessageBox.information(self, "Select User", "Select a user row first.")
            return ""
        row = selected[0].row()
        item = table.item(row, 0)
        username = item.text() if item else ""
        if not allow_self and username == (self._auth_client.username if self._auth_client else ""):
            QMessageBox.warning(self, "Invalid Operation", "Do not operate on the current admin account here.")
            return ""
        return username

    def _set_admin_actions_enabled(self, enabled: bool) -> None:
        for name in (
            "refresh_users_button",
            "mute_button",
            "unmute_button",
            "kick_button",
            "invalidate_session_button",
            "kick_session_button",
        ):
            widget = getattr(self, name, None)
            if widget:
                widget.setEnabled(enabled)

    @staticmethod
    def _query_db(path: Path, query: str, params: list[Any]) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        uri = f"file:{path.as_posix()}?mode=ro"
        try:
            with sqlite3.connect(uri, uri=True) as conn:
                conn.row_factory = sqlite3.Row
                return [dict(row) for row in conn.execute(query, params).fetchall()]
        except sqlite3.Error:
            return []

    @staticmethod
    def _execute_db(path: Path, query: str, params: list[Any]) -> int:
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as conn:
            cursor = conn.execute(query, params)
            conn.commit()
            return int(cursor.rowcount)

    @staticmethod
    def _tcp_check(host: str, port: int) -> bool:
        try:
            request(host, port, Message(type="HEARTBEAT", seq=0, body={}), timeout=0.8)
            return True
        except Exception:
            return False

    @staticmethod
    def _stretch_table(table: QTableWidget) -> None:
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        table.verticalHeader().setVisible(False)

    @staticmethod
    def _set_row(table: QTableWidget, row: int, values: list[Any]) -> None:
        for col, value in enumerate(values):
            item = QTableWidgetItem(str(value or ""))
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            table.setItem(row, col, item)

    @staticmethod
    def _format_ts(value: Any) -> str:
        try:
            ts = int(value or 0)
        except (TypeError, ValueError):
            return ""
        if ts <= 0:
            return ""
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts / 1000))

    @staticmethod
    def _short_text(value: Any, limit: int) -> str:
        text = str(value or "")
        return text if len(text) <= limit else text[:limit] + "..."
