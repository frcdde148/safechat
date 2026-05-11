"""PyQt 管理端界面。"""

from __future__ import annotations

import csv
import time
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
from common.config.settings import load_settings, service_address
from common.protocol.message import Message
from common.protocol.socket_io import request


AUTH_FLOW = ("C_AS_REQ", "AS_C_REP", "C_TGS_REQ", "TGS_C_REP", "C_V_REQ", "V_C_REP")


class AdminConsole(QMainWindow):
    """Standalone management console for users, sessions, audits, and chat moderation."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SafeChat 管理端")
        self.resize(1500, 930)
        self._settings = load_settings()
        self._auth_client: AuthClient | None = None
        self._admin_token = ""
        self._contacts: list[dict[str, Any]] = []

        root = QWidget()
        layout = QVBoxLayout(root)
        layout.addWidget(self._build_login_panel())

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_overview_tab(), "在线与禁言")
        self.tabs.addTab(self._build_user_admin_tab(), "用户与角色")
        self.tabs.addTab(self._build_sessions_tab(), "票据与会话")
        self.tabs.addTab(self._build_ip_ban_tab(), "IP 封禁")
        self.tabs.addTab(self._build_chat_records_tab(), "聊天记录")
        self.tabs.addTab(self._build_audit_tab(), "审计日志")
        self.tabs.addTab(self._build_status_tab(), "服务状态")
        layout.addWidget(self.tabs, 1)

        self.setCentralWidget(root)
        self._set_admin_actions_enabled(False)
        self.refresh_status()

    def _build_login_panel(self) -> QGroupBox:
        group = QGroupBox("管理员 Kerberos 认证")
        layout = QGridLayout(group)
        as_host, as_port = service_address("as_server")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("管理员用户名")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("管理员密码")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.as_host_input = QLineEdit(as_host)
        self.as_port_input = QSpinBox()
        self.as_port_input.setRange(1, 65535)
        self.as_port_input.setValue(as_port)
        self.login_button = QPushButton("登录认证")
        self.login_button.clicked.connect(self.login_admin)
        self.login_status = QLabel("未认证")

        layout.addWidget(QLabel("用户名"), 0, 0)
        layout.addWidget(self.username_input, 0, 1)
        layout.addWidget(QLabel("密码"), 0, 2)
        layout.addWidget(self.password_input, 0, 3)
        layout.addWidget(QLabel("AS 主机"), 1, 0)
        layout.addWidget(self.as_host_input, 1, 1)
        layout.addWidget(QLabel("AS 端口"), 1, 2)
        layout.addWidget(self.as_port_input, 1, 3)
        layout.addWidget(self.login_button, 0, 4, 2, 1)
        layout.addWidget(self.login_status, 0, 5, 2, 1)
        return group

    def _build_overview_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        actions = QHBoxLayout()
        self.refresh_users_button = QPushButton("刷新通讯录")
        self.refresh_users_button.clicked.connect(self.refresh_users)
        self.mute_button = QPushButton("禁言选中用户")
        self.mute_button.clicked.connect(self.mute_selected_user)
        self.unmute_button = QPushButton("解除禁言")
        self.unmute_button.clicked.connect(self.unmute_selected_user)
        self.kick_button = QPushButton("踢出在线用户")
        self.kick_button.clicked.connect(self.kick_selected_user)
        self.duration_input = QSpinBox()
        self.duration_input.setRange(1, 1440)
        self.duration_input.setValue(10)
        self.reason_input = QLineEdit("管理员禁言")
        actions.addWidget(self.refresh_users_button)
        actions.addWidget(QLabel("禁言分钟"))
        actions.addWidget(self.duration_input)
        actions.addWidget(QLabel("原因"))
        actions.addWidget(self.reason_input, 1)
        actions.addWidget(self.mute_button)
        actions.addWidget(self.unmute_button)
        actions.addWidget(self.kick_button)
        layout.addLayout(actions)

        self.users_table = QTableWidget(0, 8)
        self.users_table.setHorizontalHeaderLabels(
            ["用户", "角色", "状态", "IP", "最后在线", "是否禁言", "禁言到期", "会话"]
        )
        self._stretch_table(self.users_table)
        layout.addWidget(self.users_table, 1)
        return tab

    def _build_user_admin_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        create_actions = QHBoxLayout()
        self.create_username_input = QLineEdit()
        self.create_username_input.setPlaceholderText("新用户名")
        self.create_password_input = QLineEdit()
        self.create_password_input.setPlaceholderText("初始密码")
        self.create_password_input.setEchoMode(QLineEdit.Password)
        self.create_role_selector = QComboBox()
        self.create_role_selector.addItem("普通用户", "user")
        self.create_role_selector.addItem("管理员", "admin")
        self.create_user_button = QPushButton("创建用户")
        self.create_user_button.clicked.connect(self.create_user)
        create_actions.addWidget(QLabel("新用户"))
        create_actions.addWidget(self.create_username_input)
        create_actions.addWidget(QLabel("密码"))
        create_actions.addWidget(self.create_password_input)
        create_actions.addWidget(QLabel("角色"))
        create_actions.addWidget(self.create_role_selector)
        create_actions.addWidget(self.create_user_button)
        layout.addLayout(create_actions)

        actions = QHBoxLayout()
        self.refresh_roles_button = QPushButton("刷新用户")
        self.refresh_roles_button.clicked.connect(self.refresh_user_roles)
        self.role_selector = QComboBox()
        self.role_selector.addItem("普通用户", "user")
        self.role_selector.addItem("管理员", "admin")
        self.apply_role_button = QPushButton("设置选中角色")
        self.apply_role_button.clicked.connect(self.set_selected_user_role)
        self.reset_password_input = QLineEdit()
        self.reset_password_input.setPlaceholderText("新密码")
        self.reset_password_input.setEchoMode(QLineEdit.Password)
        self.reset_password_button = QPushButton("重置选中用户密码")
        self.reset_password_button.clicked.connect(self.reset_selected_user_password)
        self.delete_user_button = QPushButton("删除选中用户")
        self.delete_user_button.clicked.connect(self.delete_selected_user)
        actions.addWidget(self.refresh_roles_button)
        actions.addWidget(QLabel("角色"))
        actions.addWidget(self.role_selector)
        actions.addWidget(self.apply_role_button)
        actions.addWidget(QLabel("新密码"))
        actions.addWidget(self.reset_password_input)
        actions.addWidget(self.reset_password_button)
        actions.addWidget(self.delete_user_button)
        actions.addStretch(1)
        layout.addLayout(actions)

        self.roles_table = QTableWidget(0, 5)
        self.roles_table.setHorizontalHeaderLabels(["用户", "AS 角色", "聊天角色", "AS 创建时间", "聊天创建时间"])
        self._stretch_table(self.roles_table)
        layout.addWidget(self.roles_table, 1)
        return tab

    def _build_sessions_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        actions = QHBoxLayout()
        self.refresh_sessions_button = QPushButton("刷新会话")
        self.refresh_sessions_button.clicked.connect(self.refresh_sessions)
        self.invalidate_session_button = QPushButton("使选中用户会话失效")
        self.invalidate_session_button.clicked.connect(self.invalidate_selected_sessions)
        self.kick_session_button = QPushButton("踢出选中在线用户")
        self.kick_session_button.clicked.connect(self.kick_selected_session_user)
        actions.addWidget(self.refresh_sessions_button)
        actions.addWidget(self.invalidate_session_button)
        actions.addWidget(self.kick_session_button)
        actions.addStretch(1)
        layout.addLayout(actions)

        self.sessions_table = QTableWidget(0, 9)
        self.sessions_table.setHorizontalHeaderLabels(
            ["用户", "会话", "IP", "TGT 签发", "TGT 过期", "服务票据签发", "服务票据过期", "最后在线", "状态"]
        )
        self._stretch_table(self.sessions_table)
        layout.addWidget(self.sessions_table, 1)
        return tab

    def _build_ip_ban_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        actions = QHBoxLayout()
        self.ban_ip_input = QLineEdit()
        self.ban_ip_input.setPlaceholderText("IP 地址")
        self.ban_minutes_input = QSpinBox()
        self.ban_minutes_input.setRange(1, 1440)
        self.ban_minutes_input.setValue(30)
        self.ban_reason_input = QLineEdit("管理员封禁")
        self.add_ip_ban_button = QPushButton("封禁 IP")
        self.add_ip_ban_button.clicked.connect(self.add_ip_ban)
        self.remove_ip_ban_button = QPushButton("解封选中 IP")
        self.remove_ip_ban_button.clicked.connect(self.remove_selected_ip_ban)
        self.refresh_ip_bans_button = QPushButton("刷新 IP 封禁")
        self.refresh_ip_bans_button.clicked.connect(self.refresh_ip_bans)
        actions.addWidget(QLabel("IP"))
        actions.addWidget(self.ban_ip_input)
        actions.addWidget(QLabel("分钟"))
        actions.addWidget(self.ban_minutes_input)
        actions.addWidget(QLabel("原因"))
        actions.addWidget(self.ban_reason_input, 1)
        actions.addWidget(self.add_ip_ban_button)
        actions.addWidget(self.remove_ip_ban_button)
        actions.addWidget(self.refresh_ip_bans_button)
        layout.addLayout(actions)

        self.ip_bans_table = QTableWidget(0, 6)
        self.ip_bans_table.setHorizontalHeaderLabels(["ID", "IP", "原因", "创建时间", "过期时间", "是否生效"])
        self._stretch_table(self.ip_bans_table)
        layout.addWidget(self.ip_bans_table, 1)
        return tab

    def _build_chat_records_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        filters = QHBoxLayout()
        self.chat_type_filter = QComboBox()
        self.chat_type_filter.addItem("全部", "All")
        self.chat_type_filter.addItem("群聊", "group")
        self.chat_type_filter.addItem("私聊", "private")
        self.chat_user_filter = QLineEdit()
        self.chat_user_filter.setPlaceholderText("发送者/接收者过滤")
        self.refresh_chat_button = QPushButton("查询聊天记录")
        self.refresh_chat_button.clicked.connect(self.refresh_chat_records)
        filters.addWidget(QLabel("类型"))
        filters.addWidget(self.chat_type_filter)
        filters.addWidget(QLabel("用户"))
        filters.addWidget(self.chat_user_filter, 1)
        filters.addWidget(self.refresh_chat_button)
        layout.addLayout(filters)

        self.chat_table = QTableWidget(0, 8)
        self.chat_table.setHorizontalHeaderLabels(["ID", "时间", "类型", "会话", "发送者", "接收者", "内容", "文件"])
        self._stretch_table(self.chat_table)
        layout.addWidget(self.chat_table, 1)
        return tab

    def _build_audit_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        filters = QHBoxLayout()
        self.audit_db_filter = QComboBox()
        self.audit_db_filter.addItem("AS 认证服务器", "as")
        self.audit_db_filter.addItem("TGS 票据服务器", "tgs")
        self.audit_db_filter.addItem("聊天服务器", "chat")
        self.audit_action_filter = QLineEdit()
        self.audit_action_filter.setPlaceholderText("操作类型过滤")
        self.refresh_audit_button = QPushButton("查询审计日志")
        self.refresh_audit_button.clicked.connect(self.refresh_audit_logs)
        self.export_audit_button = QPushButton("导出 CSV")
        self.export_audit_button.clicked.connect(self.export_audit_csv)
        filters.addWidget(QLabel("数据库"))
        filters.addWidget(self.audit_db_filter)
        filters.addWidget(QLabel("操作"))
        filters.addWidget(self.audit_action_filter, 1)
        filters.addWidget(self.refresh_audit_button)
        filters.addWidget(self.export_audit_button)
        layout.addLayout(filters)

        self.audit_table = QTableWidget(0, 7)
        self.audit_table.setHorizontalHeaderLabels(["ID", "时间", "用户", "IP", "操作", "内容", "签名"])
        self._stretch_table(self.audit_table)
        layout.addWidget(self.audit_table, 1)
        return tab

    def _build_status_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.refresh_status_button = QPushButton("刷新服务状态")
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
            "client_type": "admin_console",
        }
        if not payload["username"] or not payload["password"]:
            QMessageBox.warning(self, "认证失败", "请输入管理员用户名和密码。")
            return
        self.login_button.setEnabled(False)
        try:
            client = AuthClient(payload)
            for stage in AUTH_FLOW:
                ok, detail = client.run_stage(stage)
                if not ok:
                    raise RuntimeError(detail)
            self._auth_client = client
            self._admin_token = client.request_admin_token()
            self.password_input.clear()
            self.login_status.setText(f"已认证：{client.username}")
            self._set_admin_actions_enabled(True)
            self.refresh_all()
        except Exception as exc:
            self._auth_client = None
            self._admin_token = ""
            self.login_status.setText("认证失败")
            self._set_admin_actions_enabled(False)
            QMessageBox.critical(self, "认证失败", str(exc))
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
            QMessageBox.critical(self, "刷新失败", str(exc))
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
                    self._role_text(user.get("role", "user")),
                    self._status_label(user.get("status", "")),
                    user.get("client_ip", ""),
                    self._format_ts(user.get("last_seen", 0)),
                    "是" if user.get("muted") else "否",
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
                reason=self.reason_input.text().strip() or "管理员禁言",
            )
        except Exception as exc:
            QMessageBox.critical(self, "禁言失败", str(exc))
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
            QMessageBox.critical(self, "解除禁言失败", str(exc))
            return
        self.refresh_users()
        self.refresh_audit_logs()

    def kick_selected_user(self) -> None:
        username = self._selected_username(self.users_table)
        self._kick_user(username)

    def refresh_user_roles(self) -> None:
        as_users = {row["username"]: row for row in self._as_admin_request("AS_ADMIN_LIST_USERS").get("users", [])}
        chat_users = {row["username"]: row for row in (self._contacts or [])}
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
                    self._role_text(as_users.get(username, {}).get("role", "")),
                    self._role_text(chat_users.get(username, {}).get("role", "")),
                    self._format_ts(as_users.get(username, {}).get("created_at", 0)),
                    self._format_ts(chat_users.get(username, {}).get("created_at", 0)),
                ],
            )

    def set_selected_user_role(self) -> None:
        username = self._selected_username(self.roles_table, allow_self=True)
        if not username:
            return
        if username == (self._auth_client.username if self._auth_client else ""):
            QMessageBox.warning(self, "操作无效", "不能修改当前管理员自己的角色。")
            return
        role = self.role_selector.currentData()
        self._as_admin_request("AS_ADMIN_SET_ROLE", {"target_username": username, "role": role})
        if self._auth_client:
            self._auth_client.chat_admin_set_role(username, role)
        self.refresh_user_roles()
        self.refresh_users()
        QMessageBox.information(self, "角色已更新", f"{username} 当前角色为：{self._role_text(role)}。")

    def create_user(self) -> None:
        username = self.create_username_input.text().strip()
        password = self.create_password_input.text()
        role = self.create_role_selector.currentData()
        if not username or not password:
            QMessageBox.warning(self, "创建失败", "请输入用户名和初始密码。")
            return
        try:
            self._as_admin_request(
                "AS_ADMIN_CREATE_USER",
                {"username": username, "password": password, "role": role},
            )
            if self._auth_client:
                self._auth_client.chat_admin_set_role(username, role)
        except Exception as exc:
            QMessageBox.critical(self, "创建失败", str(exc))
            return
        self.create_username_input.clear()
        self.create_password_input.clear()
        self.refresh_user_roles()
        self.refresh_users()
        QMessageBox.information(self, "创建成功", f"用户 {username} 已创建。")

    def reset_selected_user_password(self) -> None:
        username = self._selected_username(self.roles_table, allow_self=True)
        password = self.reset_password_input.text()
        if not username:
            return
        if not password:
            QMessageBox.warning(self, "重置失败", "请输入新密码。")
            return
        try:
            self._as_admin_request(
                "AS_ADMIN_RESET_PASSWORD",
                {"target_username": username, "password": password},
            )
            self._kick_user(username, show_errors=False)
        except Exception as exc:
            QMessageBox.critical(self, "重置失败", str(exc))
            return
        self.reset_password_input.clear()
        self.refresh_sessions()
        QMessageBox.information(self, "密码已重置", f"{username} 的密码已更新，现有会话已失效。")

    def delete_selected_user(self) -> None:
        username = self._selected_username(self.roles_table, allow_self=True)
        if not username:
            return
        if username == (self._auth_client.username if self._auth_client else ""):
            QMessageBox.warning(self, "操作无效", "不能删除当前管理员自己。")
            return
        confirm = QMessageBox.question(
            self,
            "确认删除用户",
            f"确定删除用户 {username}？聊天记录和审计日志会保留。",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            self._as_admin_request("AS_ADMIN_DELETE_USER", {"target_username": username})
            if self._auth_client:
                self._auth_client.chat_admin_delete_user(username)
        except Exception as exc:
            QMessageBox.critical(self, "删除失败", str(exc))
            return
        self.refresh_user_roles()
        self.refresh_users()
        self.refresh_sessions()
        QMessageBox.information(self, "删除成功", f"用户 {username} 已删除。")

    def refresh_sessions(self) -> None:
        rows = self._as_admin_request("AS_ADMIN_LIST_SESSIONS").get("sessions", [])
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
                    self._status_label(item["status"]),
                ],
            )

    def invalidate_selected_sessions(self) -> None:
        username = self._selected_username(self.sessions_table, allow_self=True)
        if not username:
            return
        self._as_admin_request("AS_ADMIN_INVALIDATE_USER", {"target_username": username})
        self._kick_user(username, show_errors=False)
        self.refresh_sessions()
        self.refresh_users()
        QMessageBox.information(self, "会话已失效", f"{username} 的活动会话已失效。")

    def kick_selected_session_user(self) -> None:
        username = self._selected_username(self.sessions_table, allow_self=True)
        self._kick_user(username)

    def add_ip_ban(self) -> None:
        ip = self.ban_ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "缺少 IP", "请输入 IP 地址。")
            return
        ban_seconds = int(self.ban_minutes_input.value()) * 60
        self._as_admin_request(
            "AS_ADMIN_BAN_IP",
            {
                "ip_address": ip,
                "reason": self.ban_reason_input.text().strip(),
                "ban_seconds": ban_seconds,
            },
        )
        self.refresh_ip_bans()

    def refresh_ip_bans(self) -> None:
        rows = self._as_admin_request("AS_ADMIN_LIST_IP_BANS").get("ip_bans", [])
        self.ip_bans_table.setRowCount(0)
        for item in rows:
            created_at = int(item.get("created_at", 0) or 0)
            expires = int(item.get("expires_at", 0) or 0)
            row = self.ip_bans_table.rowCount()
            self.ip_bans_table.insertRow(row)
            self._set_row(
                self.ip_bans_table,
                row,
                [
                    item["id"],
                    item["ip_address"],
                    item["reason"],
                    self._format_ts(created_at),
                    self._format_ts(expires),
                    "是" if item.get("active") else "否",
                ],
            )

    def remove_selected_ip_ban(self) -> None:
        selected = self.ip_bans_table.selectedItems()
        if not selected:
            QMessageBox.information(self, "请选择 IP", "请先选择一条 IP 封禁记录。")
            return
        row = selected[0].row()
        item = self.ip_bans_table.item(row, 1)
        ip = item.text().strip() if item else ""
        if not ip:
            return
        self._as_admin_request("AS_ADMIN_UNBAN_IP", {"ip_address": ip})
        self.refresh_ip_bans()
        self.refresh_audit_logs()

    def refresh_chat_records(self) -> None:
        chat_type = self.chat_type_filter.currentData()
        user_filter = self.chat_user_filter.text().strip()
        rows = self._auth_client.chat_admin_list_messages(chat_type, user_filter, 200) if self._auth_client else []
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
                    self._chat_type_text(item["chat_type"]),
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
                    self._action_text(item["action_type"]),
                    self._short_text(item["content_enc"], 160),
                    self._short_text(item["signature"], 60),
                ],
            )

    def export_audit_csv(self) -> None:
        target, _ = QFileDialog.getSaveFileName(self, "导出审计 CSV", "safechat_audit.csv", "CSV 文件 (*.csv)")
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
        QMessageBox.information(self, "导出完成", target)

    def refresh_status(self) -> None:
        lines = ["SafeChat 管理端状态", ""]
        for section in ("as_server", "tgs_server", "chat_server"):
            host, port = service_address(section)
            status = "在线" if self._tcp_check(host, port) else "不可达"
            lines.append(f"{self._service_text(section)}：{host}:{port}    {status}")
        lines.append("")
        lines.append("管理接口：禁言、解除禁言、踢出由 ChatServer 执行。")
        lines.append("数据来源：管理端只通过 AS、TGS、ChatServer 的接口获取数据，不直接打开 SQLite 文件。")
        self.status_text.setPlainText("\n".join(lines))

    def _audit_rows(self, limit: int) -> list[dict[str, Any]]:
        role = self.audit_db_filter.currentData()
        action_filter = self.audit_action_filter.text().strip()
        if role == "as":
            return self._as_admin_request(
                "AS_ADMIN_AUDIT_QUERY",
                {"action_filter": action_filter, "limit": int(limit)},
            ).get("audit_logs", [])
        if role == "tgs":
            return self._tgs_admin_request(
                "TGS_ADMIN_AUDIT_QUERY",
                {"action_filter": action_filter, "limit": int(limit)},
            ).get("audit_logs", [])
        if self._auth_client:
            return self._auth_client.chat_admin_audit_query(action_filter, int(limit))
        return []

    def _kick_user(self, username: str, show_errors: bool = True) -> None:
        if not username or not self._auth_client:
            return
        try:
            self._auth_client.admin_kick_user(username)
        except Exception as exc:
            if show_errors:
                QMessageBox.critical(self, "踢出失败", str(exc))
            return
        self.refresh_users()
        self.refresh_audit_logs()

    def _selected_username(self, table: QTableWidget, allow_self: bool = False) -> str:
        selected = table.selectedItems()
        if not selected:
            QMessageBox.information(self, "请选择用户", "请先选择一个用户行。")
            return ""
        row = selected[0].row()
        item = table.item(row, 0)
        username = item.text() if item else ""
        if not allow_self and username == (self._auth_client.username if self._auth_client else ""):
            QMessageBox.warning(self, "操作无效", "不要在这里操作当前管理员账号。")
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
            "apply_role_button",
            "create_user_button",
            "reset_password_button",
            "delete_user_button",
            "add_ip_ban_button",
            "remove_ip_ban_button",
            "refresh_roles_button",
            "refresh_sessions_button",
            "refresh_ip_bans_button",
            "refresh_chat_button",
            "refresh_audit_button",
            "export_audit_button",
        ):
            widget = getattr(self, name, None)
            if widget:
                widget.setEnabled(enabled)

    def _as_admin_request(self, action_type: str, fields: dict[str, Any] | None = None) -> dict[str, Any]:
        host, port = service_address("as_server")
        body = {"admin_token": self._admin_token, **(fields or {})}
        response = request(host, port, Message(type=action_type, seq=0, body=body), timeout=10.0)
        if response["type"] == "ERROR":
            raise RuntimeError(response["body"].get("error", "AS 管理请求失败"))
        return response["body"]

    def _tgs_admin_request(self, action_type: str, fields: dict[str, Any] | None = None) -> dict[str, Any]:
        host, port = service_address("tgs_server")
        body = {"admin_token": self._admin_token, **(fields or {})}
        response = request(host, port, Message(type=action_type, seq=0, body=body), timeout=10.0)
        if response["type"] == "ERROR":
            raise RuntimeError(response["body"].get("error", "TGS 管理请求失败"))
        return response["body"]

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

    @staticmethod
    def _role_text(value: Any) -> str:
        return {"admin": "管理员", "user": "普通用户"}.get(str(value or ""), str(value or ""))

    @staticmethod
    def _chat_type_text(value: Any) -> str:
        return {"group": "群聊", "private": "私聊", "All": "全部"}.get(str(value or ""), str(value or ""))

    @staticmethod
    def _status_label(value: Any) -> str:
        text = str(value or "")
        return {"online": "在线", "offline": "离线", "active": "有效", "invalid": "失效"}.get(text, text)

    @staticmethod
    def _service_text(value: str) -> str:
        return {
            "as_server": "AS 认证服务器",
            "tgs_server": "TGS 票据服务器",
            "chat_server": "聊天服务器",
        }.get(value, value)

    @staticmethod
    def _action_text(value: Any) -> str:
        text = str(value or "")
        return {
            "LOGIN_FAILED": "登录失败",
            "LOGIN_DENIED_DUPLICATE": "重复登录被拒绝",
            "LOGIN_AS_OK": "AS 登录成功",
            "TGS_ERROR": "TGS 错误",
            "TGS_TICKET_OK": "TGS 签发服务票据",
            "CHAT_AUTH_OK": "聊天服务认证成功",
            "CHAT_SIGN_FAILED": "聊天签名校验失败",
            "CHAT_SEND_MUTED": "禁言用户发送消息被拒绝",
            "IMAGE_SEND_MUTED": "禁言用户发送图片被拒绝",
            "CHAT_SEND_OFFLINE": "私聊离线消息",
            "CHAT_SEND": "发送聊天消息",
            "CHAT_POLL": "拉取聊天消息",
            "CHAT_SESSION_REVOKED": "聊天会话已撤销",
            "USER_LIST": "查询用户列表",
            "ADMIN_MUTE_DENIED": "禁言权限不足",
            "ADMIN_MUTE_USER": "管理员禁言用户",
            "ADMIN_UNMUTE_DENIED": "解除禁言权限不足",
            "ADMIN_UNMUTE_USER": "管理员解除禁言",
            "ADMIN_KICK_DENIED": "踢出权限不足",
            "ADMIN_KICK_USER": "管理员踢出用户",
            "AS_ADMIN_DENIED": "AS 管理权限不足",
            "AS_ADMIN_CREATE_USER": "AS 创建用户",
            "AS_ADMIN_DELETE_USER": "AS 删除用户",
            "AS_ADMIN_SET_ROLE": "AS 设置用户角色",
            "AS_ADMIN_RESET_PASSWORD": "AS 重置用户密码",
            "AS_ADMIN_INVALIDATE_USER": "AS 使用户会话失效",
            "AS_ADMIN_BAN_IP": "AS 封禁 IP",
            "AS_ADMIN_UNBAN_IP": "AS 解封 IP",
            "AS_ADMIN_TOKEN_DENIED": "管理员令牌申请被拒绝",
            "AS_ADMIN_TOKEN_OK": "管理员令牌签发成功",
            "TGS_ADMIN_DENIED": "TGS 管理权限不足",
            "CHAT_ADMIN_LIST_MESSAGES": "管理端查询聊天记录",
            "CHAT_ADMIN_SET_ROLE": "聊天服务设置用户角色",
            "CHAT_ADMIN_DELETE_USER": "聊天服务删除用户副本",
        }.get(text, text)
