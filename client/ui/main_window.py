"""SafeChat client main window."""

from __future__ import annotations

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
        self.resize(1280, 760)
        self.setMinimumSize(1080, 680)
        self.setStyleSheet(APP_STYLE)

        self.stack = QStackedWidget()
        self.login_view = LoginView()
        self.chat_view = ChatView()
        self.stack.addWidget(self.login_view)
        self.stack.addWidget(self.chat_view)
        self.setCentralWidget(self.stack)

        self._stage_index = 0
        self._stage_timer = QTimer(self)
        self._stage_timer.setInterval(360)
        self._stage_timer.timeout.connect(self._advance_demo_auth)
        self.login_view.login_requested.connect(self._start_demo_auth)

    def _start_demo_auth(self, payload: dict) -> None:
        """Run a local UI authentication demo until real controllers are wired."""
        if not payload["username"]:
            self.login_view.set_status("请输入用户名", "error")
            return
        if not payload["password"]:
            self.login_view.set_status("请输入密码", "error")
            return

        self.login_view.login_button.setEnabled(False)
        self.login_view.auth_flow.reset()
        self.login_view.set_status("认证中", "warn")
        self._stage_index = 0
        self._stage_timer.start()

    def _advance_demo_auth(self) -> None:
        if self._stage_index > 0:
            previous_stage = AUTH_STAGES[self._stage_index - 1][0]
            self.login_view.auth_flow.mark_success(previous_stage)

        if self._stage_index >= len(AUTH_STAGES):
            self._stage_timer.stop()
            username = self.login_view.username_input.text().strip()
            chat_host = self.login_view.chat_host_input.text().strip()
            chat_port = self.login_view.chat_port_input.value()
            self.chat_view.current_user_label.setText(username)
            self.chat_view.server_status.set_value(f"{chat_host}:{chat_port}", "okBadge")
            self.chat_view.heartbeat_status.set_value("刚刚", "okBadge")
            self.login_view.set_status("认证通过", "ok")
            self.login_view.login_button.setEnabled(True)
            self.stack.setCurrentWidget(self.chat_view)
            return

        current_stage = AUTH_STAGES[self._stage_index][0]
        self.login_view.auth_flow.mark_running(current_stage)
        self._stage_index += 1
