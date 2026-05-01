"""SafeChat client main window."""

from __future__ import annotations

import json

from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import QMainWindow, QStackedWidget

from client.ui.auth_flow_view import AUTH_STAGES
from client.ui.chat_view import ChatView
from client.ui.login_view import LoginView
from client.ui.styles import APP_STYLE


class MainWindow(QMainWindow):
    """Top-level client window that switches between login and chat views."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SafeChat Client")
        self.resize(1680, 980)
        self.setMinimumSize(1360, 820)
        self.setStyleSheet(APP_STYLE)

        self.stack = QStackedWidget()
        self.login_view = LoginView()
        self.chat_view = ChatView()
        self.stack.addWidget(self.login_view)
        self.stack.addWidget(self.chat_view)
        self.setCentralWidget(self.stack)

        self._stage_index = 0
        self._auth_payload: dict = {}
        self._stage_timer = QTimer(self)
        self._stage_timer.setInterval(1100)
        self._stage_timer.timeout.connect(self._advance_demo_auth)
        self.login_view.login_requested.connect(self._start_demo_auth)
        self.login_view.enter_chat_requested.connect(self._enter_chat)

    def _start_demo_auth(self, payload: dict) -> None:
        """Run a local UI authentication demo until real controllers are wired."""
        self.login_view.enter_chat_button.setEnabled(False)
        if not payload["username"]:
            self.login_view.set_status("请输入用户名", "error")
            return
        if not payload["password"]:
            self.login_view.set_status("请输入密码", "error")
            return

        self.login_view.login_button.setEnabled(False)
        self.login_view.auth_flow.reset()
        self.login_view.set_status("认证中", "warn")
        self._auth_payload = payload
        self._stage_index = 0
        self._stage_timer.start()

    def _advance_demo_auth(self) -> None:
        if self._stage_index > 0:
            previous_stage = AUTH_STAGES[self._stage_index - 1][0]
            self.login_view.auth_flow.mark_success(previous_stage)

        if self._stage_index >= len(AUTH_STAGES):
            self._stage_timer.stop()
            self.login_view.set_status("认证通过", "ok")
            self.login_view.login_button.setEnabled(True)
            self.login_view.enter_chat_button.setEnabled(True)
            self.login_view.auth_flow.append_detail(
                "认证完成",
                "已获得 ChatServer 服务票据和会话密钥 Kc,v。可继续查看上方报文细节，确认后点击“进入聊天室”。",
            )
            return

        current_stage, current_label = AUTH_STAGES[self._stage_index]
        self.login_view.auth_flow.mark_running(current_stage)
        self.login_view.auth_flow.append_detail(
            current_label,
            self._build_demo_message_detail(current_stage),
        )
        self._stage_index += 1

    def _enter_chat(self) -> None:
        username = self.login_view.username_input.text().strip()
        chat_host = self.login_view.chat_host_input.text().strip()
        chat_port = self.login_view.chat_port_input.value()
        self.chat_view.current_user_label.setText(username)
        self.chat_view.server_status.set_value(f"{chat_host}:{chat_port}", "okBadge")
        self.chat_view.heartbeat_status.set_value("刚刚", "okBadge")
        self.stack.setCurrentWidget(self.chat_view)

    def _build_demo_message_detail(self, stage_code: str) -> str:
        username = self._auth_payload.get("username", "alice")
        as_host, as_port = self._auth_payload.get("as", ("127.0.0.1", 8000))
        tgs_host, tgs_port = self._auth_payload.get("tgs", ("127.0.0.1", 8001))
        chat_host, chat_port = self._auth_payload.get("chat", ("127.0.0.1", 9000))
        samples = {
            "C_AS_REQ": {
                "direction": f"Client -> AS({as_host}:{as_port})",
                "msg_type": "C_AS_REQ",
                "payload": {
                    "client_id": username,
                    "tgs_id": "TGS",
                    "nonce": "n1-demo",
                },
                "digest": "sha256(payload)",
                "signature": "RSA_sign(client_private_key, digest)",
            },
            "AS_C_REP": {
                "direction": "AS -> Client",
                "msg_type": "AS_C_REP",
                "payload": {
                    "session_key": "Kc,tgs",
                    "ticket_tgt": "E(Ktgs, client_id | client_addr | Kc,tgs | lifetime)",
                    "nonce": "n1-demo",
                },
                "digest": "sha256(payload)",
                "signature": "RSA_sign(as_private_key, digest)",
            },
            "C_TGS_REQ": {
                "direction": f"Client -> TGS({tgs_host}:{tgs_port})",
                "msg_type": "C_TGS_REQ",
                "payload": {
                    "service_id": "ChatServer",
                    "ticket_tgt": "base64(TGT)",
                    "authenticator": "E(Kc,tgs, client_id | timestamp)",
                },
                "digest": "sha256(payload)",
                "signature": "RSA_sign(client_private_key, digest)",
            },
            "TGS_C_REP": {
                "direction": "TGS -> Client",
                "msg_type": "TGS_C_REP",
                "payload": {
                    "session_key": "Kc,v",
                    "service_ticket": "E(Kv, client_id | client_addr | Kc,v | lifetime)",
                },
                "digest": "sha256(payload)",
                "signature": "RSA_sign(tgs_private_key, digest)",
            },
            "C_V_REQ": {
                "direction": f"Client -> ChatServer({chat_host}:{chat_port})",
                "msg_type": "C_V_REQ",
                "payload": {
                    "service_ticket": "base64(Service Ticket)",
                    "authenticator": "E(Kc,v, client_id | timestamp)",
                },
                "digest": "sha256(payload)",
                "signature": "RSA_sign(client_private_key, digest)",
            },
            "V_C_REP": {
                "direction": "ChatServer -> Client",
                "msg_type": "V_C_REP",
                "payload": {
                    "mutual_auth": "E(Kc,v, timestamp + 1)",
                    "chat_room": "public",
                },
                "digest": "sha256(payload)",
                "signature": "RSA_sign(chat_server_private_key, digest)",
            },
        }
        return json.dumps(samples[stage_code], ensure_ascii=False, indent=2)
