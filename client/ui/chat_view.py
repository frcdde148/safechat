"""Main chat screen."""

from __future__ import annotations

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class MessageBubble(QFrame):
    """Chat bubble for self, peer, system, and security messages."""

    def __init__(self, text: str, kind: str = "peer", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("messageBubble")
        label = QLabel(text)
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextSelectableByMouse)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)

        if kind == "self":
            label.setStyleSheet(self._bubble_style("#dbeafe", "#1e3a8a"))
            layout.addStretch(1)
            layout.addWidget(label, 0)
        elif kind == "system":
            label.setAlignment(Qt.AlignCenter)
            label.setStyleSheet(self._bubble_style("#e2e8f0", "#475569"))
            layout.addStretch(1)
            layout.addWidget(label, 0)
            layout.addStretch(1)
        elif kind == "security":
            label.setStyleSheet(self._bubble_style("#ffedd5", "#9a3412"))
            layout.addWidget(label, 1)
        else:
            label.setStyleSheet(self._bubble_style("#ffffff", "#1f2937"))
            layout.addWidget(label, 0)
            layout.addStretch(1)

    @staticmethod
    def _bubble_style(background: str, color: str) -> str:
        return (
            f"background: {background}; color: {color}; border: 1px solid #e2e8f0; "
            "border-radius: 8px; padding: 9px 12px;"
        )


class StatusLine(QWidget):
    """Compact key-value status row."""

    def __init__(self, name: str, value: str, badge: str = "mutedBadge") -> None:
        super().__init__()
        self.name_label = QLabel(name)
        self.name_label.setObjectName("hint")
        self.value_label = QLabel(value)
        self.value_label.setObjectName(badge)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.name_label)
        layout.addStretch(1)
        layout.addWidget(self.value_label)

    def set_value(self, value: str, badge: str = "mutedBadge") -> None:
        self.value_label.setText(value)
        self.value_label.setObjectName(badge)
        self.value_label.style().unpolish(self.value_label)
        self.value_label.style().polish(self.value_label)


class ChatView(QWidget):
    """Three-column chat workspace."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.current_user_label = QLabel("alice")
        self.current_user_label.setObjectName("okBadge")
        self.user_list = QListWidget()
        self.session_selector = QComboBox()
        self.message_area = QVBoxLayout()
        self.message_input = QTextEdit()

        self.session_type_status = StatusLine("会话类型", "群聊", "okBadge")
        self.server_status = StatusLine("连接服务器", "127.0.0.1:9000", "okBadge")
        self.auth_status = StatusLine("认证状态", "认证通过", "okBadge")
        self.key_status = StatusLine("会话密钥", "Kc,v 已建立", "okBadge")
        self.heartbeat_status = StatusLine("最近心跳", "未开始", "warnBadge")
        self.crypto_status = StatusLine("加密状态", "DES + HMAC", "okBadge")
        self.security_status = StatusLine("安全事件", "无异常", "okBadge")

        self._build_ui()
        self._seed_demo_content()

    def _build_ui(self) -> None:
        root = QHBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 18)
        root.setSpacing(14)
        root.addWidget(self._left_panel(), 1)
        root.addWidget(self._center_panel(), 3)
        root.addWidget(self._right_panel(), 1)

    def _left_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        title = QLabel("用户与会话")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        layout.addWidget(QLabel("当前用户"))
        layout.addWidget(self.current_user_label)

        layout.addWidget(QLabel("会话入口"))
        self.session_selector.addItems(("群聊", "私聊 alice", "私聊 bob", "私聊 carol", "私聊 dave"))
        layout.addWidget(self.session_selector)

        layout.addWidget(QLabel("在线用户"))
        layout.addWidget(self.user_list, 1)
        return panel

    def _center_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        title = QLabel("消息")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        scroll_content = QWidget()
        self.message_area.setContentsMargins(0, 0, 0, 0)
        self.message_area.setSpacing(8)
        self.message_area.addStretch(1)
        scroll_content.setLayout(self.message_area)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll, 1)

        self.message_input.setPlaceholderText("输入消息")
        self.message_input.setFixedHeight(76)
        layout.addWidget(self.message_input)

        button_row = QHBoxLayout()
        file_button = QPushButton("文件")
        file_button.setObjectName("secondaryButton")
        send_button = QPushButton("发送")
        button_row.addWidget(file_button)
        button_row.addStretch(1)
        button_row.addWidget(send_button)
        layout.addLayout(button_row)
        return panel

    def _right_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        title = QLabel("信息与状态")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)
        layout.addWidget(self.session_type_status)
        layout.addWidget(self.server_status)
        layout.addWidget(self.auth_status)
        layout.addWidget(self.key_status)
        layout.addWidget(self.heartbeat_status)
        layout.addWidget(self.crypto_status)
        layout.addWidget(self.security_status)

        security_title = QLabel("安全提示")
        security_title.setObjectName("sectionTitle")
        layout.addSpacing(8)
        layout.addWidget(security_title)
        layout.addWidget(self._tip("CHAT_SEND: 加密 + HMAC + 签名", "okBadge"))
        layout.addWidget(self._tip("USER_LIST: 加密 + HMAC", "mutedBadge"))
        layout.addWidget(self._tip("异常事件将进入审计日志", "warnBadge"))
        layout.addStretch(1)
        return panel

    def add_message(self, text: str, kind: str = "peer") -> None:
        self.message_area.insertWidget(self.message_area.count() - 1, MessageBubble(text, kind))

    def _seed_demo_content(self) -> None:
        users = (
            ("alice", "认证通过"),
            ("bob", "在线"),
            ("carol", "离线"),
            ("dave", "异常断开"),
        )
        for username, status in users:
            item = QListWidgetItem(f"{username}    {status}")
            self.user_list.addItem(item)

        self.add_message("系统通知：已进入群聊", "system")
        self.add_message("安全提示：会话密钥已建立，消息将加密传输", "security")
        self.add_message("bob：你好，认证流程已经完成", "peer")
        self.add_message("alice：收到，准备发送签名消息", "self")

    @staticmethod
    def _tip(text: str, badge: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName(badge)
        label.setWordWrap(True)
        return label
