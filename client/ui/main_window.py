"""SafeChat client main window."""

from __future__ import annotations

from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import QMainWindow, QStackedWidget

from client.net.auth_client import AuthClient
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
        self._auth_client: AuthClient | None = None
        self._stage_timer = QTimer(self)
        self._stage_timer.setInterval(1100)
        self._stage_timer.timeout.connect(self._advance_demo_auth)
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(1500)
        self._poll_timer.timeout.connect(self._poll_chat_messages)
        self.login_view.login_requested.connect(self._start_demo_auth)
        self.login_view.enter_chat_requested.connect(self._enter_chat)
        self.chat_view.message_send_requested.connect(self._send_chat_message)

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
        self._auth_client = AuthClient(payload)
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

        if not self._auth_client:
            self._stage_timer.stop()
            self.login_view.set_status("认证客户端未初始化", "error")
            return

        current_stage, current_label = AUTH_STAGES[self._stage_index]
        self.login_view.auth_flow.mark_running(current_stage)
        ok, detail = self._auth_client.run_stage(current_stage)
        self.login_view.auth_flow.append_detail(
            current_label,
            detail,
        )
        if not ok:
            self._stage_timer.stop()
            self.login_view.auth_flow.mark_failed(current_stage)
            self.login_view.set_status("认证失败", "error")
            self.login_view.login_button.setEnabled(True)
            return
        self._stage_index += 1

    def _enter_chat(self) -> None:
        username = self._auth_payload.get("username", self.login_view.username_input.text().strip())
        chat_host = self.login_view.chat_host_input.text().strip()
        chat_port = self.login_view.chat_port_input.value()
        if self._auth_client:
            chat_host = self._auth_client.chat_host
            chat_port = self._auth_client.chat_port
        self.chat_view.current_user_label.setText(username)
        self.chat_view.server_status.set_value(f"{chat_host}:{chat_port}", "okBadge")
        self.chat_view.heartbeat_status.set_value("刚刚", "okBadge")
        self.stack.setCurrentWidget(self.chat_view)
        self._refresh_online_users()
        self._poll_timer.start()

    def _send_chat_message(self, text: str) -> None:
        if not self._auth_client:
            self.chat_view.add_message("系统提示：尚未完成认证，不能发送消息", "security")
            self.chat_view.security_status.set_value("未认证", "errorBadge")
            return

        self.chat_view.send_button.setEnabled(False)
        self.chat_view.add_message(f"{self._auth_client.username}：{text}", "self")
        try:
            result = self._auth_client.send_chat_message(text)
        except Exception as exc:
            self.chat_view.add_message(f"安全提示：消息发送失败，{exc}", "security")
            self.chat_view.security_status.set_value("发送失败", "errorBadge")
        else:
            self.chat_view.message_input.clear()
            self.chat_view.add_message(f"安全回执：{result['ack']}", "security")
            self.chat_view.security_status.set_value("加密与签名已通过", "okBadge")
            self.chat_view.heartbeat_status.set_value("刚刚", "okBadge")
        finally:
            self.chat_view.send_button.setEnabled(True)

    def _poll_chat_messages(self) -> None:
        if not self._auth_client or self.stack.currentWidget() is not self.chat_view:
            return
        try:
            messages = self._auth_client.poll_chat_messages()
        except Exception as exc:
            self.chat_view.security_status.set_value("轮询失败", "errorBadge")
            self.chat_view.add_message(f"安全提示：拉取群聊消息失败，{exc}", "security")
            self._poll_timer.stop()
            return

        for message in messages:
            if message["sender"] == self._auth_client.username:
                continue
            self.chat_view.add_message(f"{message['sender']}：{message['text']}", "peer")
        if messages:
            self.chat_view.heartbeat_status.set_value("刚刚", "okBadge")
            self.chat_view.security_status.set_value("群聊同步正常", "okBadge")
        self._refresh_online_users()

    def _refresh_online_users(self) -> None:
        if not self._auth_client:
            return
        try:
            users = self._auth_client.fetch_online_users()
        except Exception as exc:
            self.chat_view.security_status.set_value("用户列表异常", "errorBadge")
            self.chat_view.add_message(f"安全提示：刷新在线用户失败，{exc}", "security")
            return
        self.chat_view.set_online_users(users)
