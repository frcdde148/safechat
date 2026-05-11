"""Main chat screen."""

from __future__ import annotations

import base64

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class MessageBubble(QFrame):
    """Chat bubble for self, peer, system, and security messages with avatar and username."""

    def __init__(self, text: str, kind: str = "peer", ciphertext: str = "", image_data: str = "", file_name: str = "", username: str = "", timestamp: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("messageBubble")
        self.text = text
        self.ciphertext = ciphertext
        self.kind = kind
        self.image_data = image_data
        self.file_name = file_name
        self.username = username
        self.show_cipher = False
        self.timestamp = timestamp
        
        # Main layout
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(8)

        # Create avatar
        self.avatar_label = QLabel()
        self.avatar_label.setFixedSize(40, 40)
        self.avatar_label.setAlignment(Qt.AlignCenter)
        self.avatar_label.setText(self._avatar_initial(username))
        self.avatar_label.setStyleSheet(self._avatar_style(username))
        
        # Create content widget (username + message + time)
        self.content_widget = QWidget()
        content_layout = QVBoxLayout(self.content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(2)
        
        # Username label
        self.username_label = QLabel(username)
        self.username_label.setStyleSheet("font-size: 24px; color: #374151; font-weight: 600;")
        
        # Timestamp label
        self.timestamp_label = QLabel(self.timestamp)
        self.timestamp_label.setStyleSheet("font-size: 11px; color: #9ca3af;")
        
        # Message content
        if image_data:
            # Show image (clickable)
            self.full_image_data = image_data
            self.message_label = QLabel()
            pixmap = QPixmap()
            pixmap.loadFromData(base64.b64decode(image_data))
            if pixmap.width() > 300:
                scaled_pixmap = pixmap.scaledToWidth(300, Qt.SmoothTransformation)
            else:
                scaled_pixmap = pixmap
            self.message_label.setPixmap(scaled_pixmap)
            self.message_label.setAlignment(Qt.AlignCenter)
            self.message_label.setCursor(Qt.PointingHandCursor)
            self.message_label.mousePressEvent = lambda e: self._show_full_image()
        else:
            # Show text
            self.message_label = QLabel(text)
            self.message_label.setWordWrap(True)
            self.message_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            self.full_image_data = ""

        # Build layout based on message type
        if kind == "self":
            # Self message: avatar on right, content on left
            self.message_label.setStyleSheet(self._bubble_style("#dbeafe", "#1e3a8a", is_self=True))
            self.message_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
            
            # Create message widget with timestamp
            message_widget = QWidget()
            message_layout = QHBoxLayout(message_widget)
            message_layout.setContentsMargins(0, 0, 0, 0)
            message_layout.addWidget(self.message_label, 1)
            self.timestamp_label.setAlignment(Qt.AlignRight | Qt.AlignBottom)
            message_layout.addWidget(self.timestamp_label, 0)
            
            content_layout.addWidget(message_widget, 0)
            self.content_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
            layout.addStretch(1)
            layout.addWidget(self.content_widget, 0)
            layout.addWidget(self.avatar_label, 0)
            self.username_label.hide()
        elif kind == "system":
            # System message: centered, no avatar
            self.message_label.setAlignment(Qt.AlignCenter)
            self.message_label.setStyleSheet(self._bubble_style("#f3f4f6", "#6b7280", is_system=True))
            layout.addStretch(1)
            layout.addWidget(self.message_label, 0)
            layout.addStretch(1)
            self.avatar_label.hide()
            self.username_label.hide()
            self.timestamp_label.hide()
        elif kind == "security":
            # Security message: full width, no avatar
            self.message_label.setStyleSheet(self._bubble_style("#fffbeb", "#92400e", is_system=True))
            self.message_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
            layout.addWidget(self.message_label, 1)
            self.avatar_label.hide()
            self.username_label.hide()
            self.timestamp_label.hide()
        else:
            # Peer message: avatar on left, content on right
            self.message_label.setStyleSheet(self._bubble_style("#ffffff", "#1f2937", is_self=False))
            self.message_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
            
            # Create message widget with timestamp
            message_widget = QWidget()
            message_layout = QHBoxLayout(message_widget)
            message_layout.setContentsMargins(0, 0, 0, 0)
            message_layout.addWidget(self.message_label, 1)
            self.timestamp_label.setAlignment(Qt.AlignRight | Qt.AlignBottom)
            message_layout.addWidget(self.timestamp_label, 0)
            
            content_layout.addWidget(self.username_label, 0)
            content_layout.addWidget(message_widget, 0)
            self.content_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
            layout.addWidget(self.avatar_label, 0)
            layout.addWidget(self.content_widget, 0)
            layout.addStretch(1)

    def set_display_mode(self, show_ciphertext: bool) -> None:
        self.show_cipher = show_ciphertext
        if not self.image_data:
            if show_ciphertext and self.ciphertext:
                self.message_label.setText(self.ciphertext)
                self.message_label.setStyleSheet(self._bubble_style("#f3f4f6", "#6b7280", is_system=True) + " font-family: 'Consolas', 'Monaco', monospace; font-size: 14px;")
            else:
                self.message_label.setText(self.text)
                self._restore_style()

    def _restore_style(self) -> None:
        if self.kind == "self":
            self.message_label.setStyleSheet(self._bubble_style("#dbeafe", "#1e3a8a", is_self=True))
        elif self.kind == "system":
            self.message_label.setStyleSheet(self._bubble_style("#f3f4f6", "#6b7280", is_system=True))
        elif self.kind == "security":
            self.message_label.setStyleSheet(self._bubble_style("#fffbeb", "#92400e", is_system=True))
        else:
            self.message_label.setStyleSheet(self._bubble_style("#ffffff", "#1f2937", is_self=False))

    def _show_full_image(self) -> None:
        """Show full-size image in a dialog when clicked."""
        from PyQt5.QtWidgets import QFileDialog, QDialog, QHBoxLayout, QVBoxLayout, QScrollArea, QLabel, QPushButton
        from PyQt5.QtGui import QPixmap
        
        if not getattr(self, 'full_image_data', ''):
            return
        image_bytes = base64.b64decode(self.full_image_data)
        
        dialog = QDialog()
        dialog.setWindowTitle(self.file_name if getattr(self, 'file_name', '') else "查看图片")
        dialog.setMinimumSize(900, 620)
        layout = QVBoxLayout(dialog)
        
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        
        pixmap = QPixmap()
        pixmap.loadFromData(image_bytes)
        
        label = QLabel()
        label.setPixmap(pixmap)
        label.setAlignment(Qt.AlignCenter)
        label.setMinimumSize(pixmap.size())
        
        scroll_area.setWidget(label)
        layout.addWidget(scroll_area)
        
        button_row = QHBoxLayout()
        save_btn = QPushButton("保存图片")
        fullscreen_btn = QPushButton("全屏")
        close_btn = QPushButton("关闭")

        def save_image() -> None:
            default_name = self.file_name if getattr(self, 'file_name', '') else "safechat_image.jpg"
            target, _ = QFileDialog.getSaveFileName(
                dialog,
                "保存图片",
                default_name,
                "图片文件 (*.png *.jpg *.jpeg *.bmp);;所有文件 (*)",
            )
            if target:
                with open(target, "wb") as file:
                    file.write(image_bytes)

        def toggle_fullscreen() -> None:
            if dialog.isFullScreen():
                dialog.showNormal()
                fullscreen_btn.setText("全屏")
            else:
                dialog.showFullScreen()
                fullscreen_btn.setText("退出全屏")

        save_btn.clicked.connect(save_image)
        fullscreen_btn.clicked.connect(toggle_fullscreen)
        close_btn.clicked.connect(dialog.close)
        button_row.addWidget(save_btn)
        button_row.addWidget(fullscreen_btn)
        button_row.addStretch(1)
        button_row.addWidget(close_btn)
        layout.addLayout(button_row)
        
        dialog.showMaximized()
        dialog.exec_()

    @staticmethod
    def _avatar_initial(username: str) -> str:
        text = str(username or "").strip()
        if not text:
            return "用"
        return text[0].upper()

    @staticmethod
    def _avatar_style(username: str) -> str:
        colors = [
            "#10b981", "#3b82f6", "#8b5cf6", "#ec4899",
            "#f59e0b", "#ef4444", "#06b6d4", "#84cc16"
        ]
        if username:
            color_index = hash(username) % len(colors)
            bg_color = colors[color_index]
        else:
            bg_color = "#9ca3af"
        
        return (
            f"background: {bg_color}; color: white; border-radius: 20px; "
            "font-weight: 600; font-size: 16px; qproperty-alignment: AlignCenter;"
        )

    @staticmethod
    def _bubble_style(background: str, color: str, is_self: bool = False, is_system: bool = False) -> str:
        if is_system:
            return (
                f"background: {background}; color: {color}; "
                "border-radius: 8px; padding: 20px 32px; font-size: 28px;"
            )
        elif is_self:
            return (
                f"background: {background}; color: {color}; border: 1px solid #bfdbfe; "
                "border-radius: 16px 16px 6px 16px; padding: 24px 32px; "
                "font-size: 30px;"
            )
        else:
            return (
                f"background: {background}; color: {color}; border: 1px solid #e5e7eb; "
                "border-radius: 16px 16px 16px 6px; padding: 24px 32px; "
                "font-size: 30px;"
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

    message_send_requested = pyqtSignal(str)
    session_changed = pyqtSignal()
    return_to_group_chat_requested = pyqtSignal()
    relogin_requested = pyqtSignal()
    image_send_requested = pyqtSignal()
    private_chat_requested = pyqtSignal(str)
    mute_user_requested = pyqtSignal(str)
    unmute_user_requested = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.current_user_label = QLabel("alice")
        self.current_user_label.setObjectName("okBadge")
        self.user_list = QListWidget()
        self.group_chat_button = QPushButton("进入群聊大厅")
        self.message_area = QVBoxLayout()
        self.message_input = QTextEdit()
        self.send_button = QPushButton("发送")
        self.toggle_cipher_button = QPushButton("显示密文")
        self.show_ciphertext = False
        self.message_bubbles: list[MessageBubble] = []
        self.is_admin_user = False
        
        # Track current session
        self.current_chat_type = "group"
        self.current_recipient = ""

        self.session_type_status = StatusLine("会话类型", "群聊大厅", "okBadge")
        self.server_status = StatusLine("连接服务器", "127.0.0.1:9000", "okBadge")
        self.auth_status = StatusLine("认证状态", "认证通过", "okBadge")
        self.key_status = StatusLine("会话密钥", "Kc,v 已建立", "okBadge")
        self.heartbeat_status = StatusLine("最近心跳", "未开始", "warnBadge")
        self.crypto_status = StatusLine("加密状态", "DES + HMAC", "okBadge")
        self.security_status = StatusLine("安全事件", "无异常", "okBadge")

        self._build_ui()
        self._seed_demo_content()
        self._refresh_cipher_toggle_ui()
        self.group_chat_button.clicked.connect(self.return_to_group_chat_requested.emit)
        self.relogin_button.clicked.connect(self._on_relogin_clicked)
        self.image_button.clicked.connect(self.image_send_requested.emit)
        self.user_list.itemDoubleClicked.connect(self._emit_private_chat_from_contact)
        self.user_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.user_list.customContextMenuRequested.connect(self._show_contact_menu)

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

        layout.addWidget(self.group_chat_button)

        layout.addWidget(QLabel("通讯录"))
        layout.addWidget(self.user_list, 1)

        self.relogin_button = QPushButton("重新认证")
        self.relogin_button.setObjectName("secondaryButton")
        self.relogin_button.setToolTip("重新执行 Kerberos 六步认证，刷新 TGT、服务票据和会话密钥")
        layout.addWidget(self.relogin_button)
        return panel

    def _center_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        self.chat_title_label = QLabel("群聊大厅")
        self.chat_title_label.setObjectName("sectionTitle")
        self.chat_title_label.setAlignment(Qt.AlignCenter)
        self.chat_title_label.setStyleSheet("font-size: 34px; font-weight: 700; color: #111827;")
        layout.addWidget(self.chat_title_label)

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
        self.message_input.textChanged.connect(self._update_send_button_state)
        layout.addWidget(self.message_input)

        # Upload progress bar
        self.upload_progress = QProgressBar()
        self.upload_progress.setFixedHeight(16)
        self.upload_progress.setVisible(False)
        self.upload_progress_label = QLabel()
        self.upload_progress_label.setStyleSheet("font-size: 13px; color: #6b7280; font-weight: bold;")
        self.upload_progress_label.setVisible(False)
        layout.addWidget(self.upload_progress)
        layout.addWidget(self.upload_progress_label)

        button_row = QHBoxLayout()
        self.image_button = QPushButton("图片")
        self.image_button.setObjectName("secondaryButton")
        self.toggle_cipher_button.setObjectName("secondaryButton")
        self.toggle_cipher_button.clicked.connect(self._toggle_cipher_display)
        self.send_button.clicked.connect(self._emit_message_send_requested)
        button_row.addWidget(self.image_button)
        button_row.addWidget(self.toggle_cipher_button)
        button_row.addStretch(1)
        button_row.addWidget(self.send_button)
        layout.addLayout(button_row)
        
        # Initialize send button state
        self._update_send_button_state()
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

    def add_message(self, text: str, kind: str = "peer", ciphertext: str = "", image_data: str = "", file_name: str = "", username: str = "", timestamp: str = "") -> None:
        bubble = MessageBubble(text, kind, ciphertext, image_data, file_name, username, timestamp)
        self.message_area.insertWidget(self.message_area.count() - 1, bubble)
        if kind not in ("system", "security"):
            self.message_bubbles.append(bubble)
            bubble.set_display_mode(self.show_ciphertext)
        self._refresh_cipher_toggle_ui()

    def clear_messages(self) -> None:
        """Remove all visible message bubbles."""
        while self.message_area.count() > 1:
            item = self.message_area.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        self.message_bubbles.clear()
        self._refresh_cipher_toggle_ui()

    def _toggle_cipher_display(self) -> None:
        if not self._has_cipher_messages():
            return
        self.show_ciphertext = not self.show_ciphertext
        for bubble in self.message_bubbles:
            bubble.set_display_mode(self.show_ciphertext)
        self._refresh_cipher_toggle_ui()

    def _has_cipher_messages(self) -> bool:
        return any(bool(bubble.ciphertext) for bubble in self.message_bubbles)

    def _refresh_cipher_toggle_ui(self) -> None:
        has_cipher = self._has_cipher_messages()
        self.toggle_cipher_button.setEnabled(has_cipher)
        if self.show_ciphertext:
            self.toggle_cipher_button.setText("显示明文")
            self.toggle_cipher_button.setToolTip("当前为密文模式，点击切换回明文显示")
        else:
            self.toggle_cipher_button.setText("显示密文")
            self.toggle_cipher_button.setToolTip("展示消息加密后的密文")
        if not has_cipher:
            self.show_ciphertext = False
            self.toggle_cipher_button.setText("显示密文")
            self.toggle_cipher_button.setToolTip("当前无可切换的密文消息")

    def current_session(self) -> dict[str, str]:
        """Return selected group/private chat routing data."""
        if self.current_chat_type == "private" and self.current_recipient:
            return {
                "chat_type": "private",
                "recipient": self.current_recipient,
                "title": f"私聊 {self.current_recipient}",
            }
        return {
            "chat_type": "group",
            "recipient": "",
            "title": "群聊大厅",
        }
    
    def set_current_session(self, chat_type: str, recipient: str) -> None:
        """Set current session."""
        self.current_chat_type = chat_type
        self.current_recipient = recipient
        self.chat_title_label.setText(f"私聊 {recipient}" if chat_type == "private" and recipient else "群聊大厅")

    def set_online_users(self, users: list[dict]) -> None:
        """Replace the left-side online user list with server state."""
        self.user_list.clear()
        self.is_admin_user = False
        current_user = self.current_user_label.text()
        for user in users:
            username = user.get("username", "")
            if not username:
                continue
            status = {"online": "在线", "offline": "离线"}.get(user.get("status", "offline"), user.get("status", "离线"))
            role = user.get("role", "user")
            muted = bool(user.get("muted", False))
            client_ip = user.get("client_ip", "")
            suffix = f"    {status}"
            if role == "admin":
                suffix = f"{suffix}    管理员"
            if muted:
                suffix = f"{suffix}    已禁言"
            if client_ip:
                suffix = f"{suffix}    {client_ip}"
            item = QListWidgetItem(f"{username}{suffix}")
            item.setData(Qt.UserRole, username)
            item.setData(Qt.UserRole + 1, role)
            item.setData(Qt.UserRole + 2, muted)
            if username == current_user:
                self.is_admin_user = role == "admin"
                item.setFlags(item.flags() & ~Qt.ItemIsEnabled)
            self.user_list.addItem(item)

    def _emit_private_chat_from_contact(self, item: QListWidgetItem) -> None:
        username = item.data(Qt.UserRole) or item.text().split()[0]
        if username and username != self.current_user_label.text():
            self.private_chat_requested.emit(username)

    def _show_contact_menu(self, position) -> None:
        item = self.user_list.itemAt(position)
        if not item or not self.is_admin_user:
            return
        username = item.data(Qt.UserRole) or item.text().split()[0]
        if not username or username == self.current_user_label.text():
            return
        muted = bool(item.data(Qt.UserRole + 2))
        menu = QMenu(self)
        mute_action = menu.addAction("禁言 10 分钟")
        unmute_action = menu.addAction("解除禁言")
        unmute_action.setEnabled(muted)
        action = menu.exec_(self.user_list.mapToGlobal(position))
        if action == mute_action:
            self.mute_user_requested.emit(username)
        elif action == unmute_action:
            self.unmute_user_requested.emit(username)

    def _emit_message_send_requested(self) -> None:
        text = self.message_input.toPlainText().strip()
        if text:
            self.message_send_requested.emit(text)

    def _on_relogin_clicked(self) -> None:
        self.relogin_requested.emit()

    def _update_send_button_state(self) -> None:
        """Update send button state based on input content."""
        has_text = bool(self.message_input.toPlainText().strip())
        current_enabled = self.send_button.isEnabled()
        
        # Only update if state actually changed
        if has_text != current_enabled:
            self.send_button.setEnabled(has_text)
            if has_text:
                self.send_button.setObjectName("primaryButton")
            else:
                self.send_button.setObjectName("disabledButton")
            self.send_button.style().unpolish(self.send_button)
            self.send_button.style().polish(self.send_button)

    def show_upload_progress(self) -> None:
        """Show upload progress bar."""
        self.upload_progress.setVisible(True)
        self.upload_progress.setValue(0)
        self.upload_progress_label.setVisible(True)
        self.upload_progress_label.setText("正在准备上传...")

    def set_upload_progress(self, value: int, text: str = "") -> None:
        """Set upload progress value (0-100) and optional status text."""
        self.upload_progress.setValue(value)
        if text:
            self.upload_progress_label.setText(text)

    def hide_upload_progress(self) -> None:
        """Hide upload progress bar."""
        self.upload_progress.setVisible(False)
        self.upload_progress_label.setVisible(False)

    def _seed_demo_content(self) -> None:
        self.add_message("系统通知：已进入群聊", "system")
        self.add_message("安全提示：会话密钥已建立，消息将加密传输", "security")

    @staticmethod
    def _tip(text: str, badge: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName(badge)
        label.setWordWrap(True)
        return label
