"""登录界面组件

包含用户名密码输入、AS服务器配置、认证状态显示。

"""

from __future__ import annotations

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import (
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from common.config.settings import service_address
from client.ui.auth_flow_view import AuthFlowView


class LoginView(QWidget):
    """客户端登录视图，包含服务器配置和认证状态"""

    login_requested = pyqtSignal(dict)
    enter_chat_requested = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        # 获取默认AS服务器地址
        as_host, as_port = service_address("as_server")
        
        # 创建输入控件
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.as_host_input = QLineEdit(as_host)
        self.as_port_input = self._port_box(as_port)
        
        self.status_label = QLabel("等待登录")
        self.status_label.setObjectName("mutedBadge")
        
        # 认证流程视图
        self.auth_flow = AuthFlowView()
        
        # 进入聊天室按钮（默认禁用，认证通过后启用）
        self.enter_chat_button = QPushButton("进入聊天室")
        self.enter_chat_button.setObjectName("secondaryButton")
        self.enter_chat_button.setEnabled(False)
        self.enter_chat_button.clicked.connect(self.enter_chat_requested.emit)

        self._build_ui()

    def _build_ui(self) -> None:
        """构建登录界面布局"""
        title = QLabel("SafeChat 客户端")
        title.setObjectName("title")

        subtitle = QLabel("基于 Kerberos V4 流程的认证聊天室")
        subtitle.setObjectName("hint")

        login_panel = QFrame()
        login_panel.setObjectName("panel")
        form = QFormLayout(login_panel)
        form.setContentsMargins(18, 18, 18, 18)
        form.setSpacing(12)

        self.username_input.setPlaceholderText("用户名")
        self.password_input.setPlaceholderText("密码")
        self.password_input.setEchoMode(QLineEdit.Password)  # 密码隐藏

        form.addRow("用户名", self.username_input)
        form.addRow("密码", self.password_input)
        form.addRow("AS 地址", self._host_port_row(self.as_host_input, self.as_port_input))

        self.login_button = QPushButton("登录认证")
        self.login_button.clicked.connect(self._emit_login_requested)
        form.addRow("", self.login_button)
        form.addRow("", self.enter_chat_button)

        status_panel = QFrame()
        status_panel.setObjectName("panel")
        status_layout = QVBoxLayout(status_panel)
        status_layout.setContentsMargins(16, 16, 16, 16)
        status_title = QLabel("认证状态")
        status_title.setObjectName("sectionTitle")
        status_layout.addWidget(status_title)
        status_layout.addWidget(self.status_label)
        status_layout.addStretch(1)

        left_layout = QVBoxLayout()
        left_layout.setSpacing(14)
        left_layout.addWidget(title)
        left_layout.addWidget(subtitle)
        left_layout.addWidget(login_panel)
        left_layout.addWidget(status_panel)
        left_layout.addStretch(1)

        root = QHBoxLayout(self)
        root.setContentsMargins(28, 28, 28, 28)
        root.setSpacing(18)
        root.addLayout(left_layout, 1)
        root.addWidget(self.auth_flow, 2)

    def _emit_login_requested(self) -> None:
        """发出登录请求信号（收集表单数据）"""
        self.login_requested.emit({
            "username": self.username_input.text().strip(),
            "password": self.password_input.text(),
            "as": (self.as_host_input.text().strip(), self.as_port_input.value()),
        })

    def set_status(self, text: str, level: str = "muted") -> None:
        """更新认证状态显示"""
        object_name = {
            "ok": "okBadge",
            "warn": "warnBadge",
            "error": "errorBadge",
            "muted": "mutedBadge",
        }.get(level, "mutedBadge")
        self.status_label.setText(text)
        self.status_label.setObjectName(object_name)
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    @staticmethod
    def _port_box(value: int) -> QSpinBox:
        """创建端口输入框（范围1-65535）"""
        box = QSpinBox()
        box.setRange(1, 65535)
        box.setValue(value)
        box.setMinimumWidth(92)
        return box

    @staticmethod
    def _host_port_row(host_input: QLineEdit, port_input: QSpinBox) -> QWidget:
        """创建地址和端口的水平布局行"""
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(host_input, 1)
        layout.addWidget(port_input)
        return row
