"""主聊天窗口"""

from __future__ import annotations

import base64
import hashlib
import queue
from collections import OrderedDict

from PyQt5.QtCore import QThread, QTimer, Qt, pyqtSignal
from PyQt5.QtGui import QImage, QPixmap, QFont
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


class ThumbnailWorker(QThread):
    """后台生成图片缩略图，避免消息列表渲染时阻塞 UI 线程。"""

    thumbnail_ready = pyqtSignal(str, object)
    thumbnail_failed = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._jobs: queue.Queue[tuple[str, str] | None] = queue.Queue()

    def enqueue(self, key: str, image_data: str) -> None:
        self._jobs.put((key, image_data))

    def stop(self) -> None:
        if not self.isRunning():
            return
        self.requestInterruption()
        self._jobs.put(None)
        if not self.wait(1500):
            self.terminate()
            self.wait(500)

    def run(self) -> None:
        while not self.isInterruptionRequested():
            job = self._jobs.get()
            if job is None:
                break
            key, image_data = job
            try:
                image_bytes = base64.b64decode(image_data, validate=True)
                image = QImage.fromData(image_bytes)
                if image.isNull():
                    raise ValueError("图片数据无效")
                if image.width() > 300:
                    image = image.scaledToWidth(300, Qt.SmoothTransformation)
                self.thumbnail_ready.emit(key, image)
            except Exception:
                self.thumbnail_failed.emit(key)


class MessageBubble(QFrame):
    """聊天气泡视图，用于显示自发消息、他人消息、系统和安全提示消息。

    包含头像、用户名、消息内容（文本或图片）、时间戳以及可切换的密文/明文显示。
    """

    def __init__(self, text: str, kind: str = "peer", ciphertext: str = "", image_data: str = "", file_name: str = "", username: str = "", timestamp: str = "", hmac: str = "", sig: str = "", pubkey: str = "", parent: QWidget | None = None) -> None:
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
        self.hmac = hmac
        self.sig = sig
        self.pubkey = pubkey
        self.thumbnail_pixmap: QPixmap | None = None
        
        # 主布局
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(8)

        # 创建头像控件
        self.avatar_label = QLabel()
        self.avatar_label.setFixedSize(40, 40)
        self.avatar_label.setAlignment(Qt.AlignCenter)
        self.avatar_label.setText(self._avatar_initial(username))
        self.avatar_label.setStyleSheet(self._avatar_style(username))
        
        # 创建内容容器（包含用户名、消息内容和时间）
        self.content_widget = QWidget()
        content_layout = QVBoxLayout(self.content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(2)
        
        # 用户名标签
        self.username_label = QLabel(username)
        self.username_label.setStyleSheet("font-size: 24px; color: #374151; font-weight: 600;")
        
        # 时间戳标签
        self.timestamp_label = QLabel(self.timestamp)
        self.timestamp_label.setStyleSheet("font-size: 14px; color: #9ca3af;")
        
        # 消息内容（图片或文本）
        if image_data or file_name:
            # 图片数据可能很大，先显示占位，缩略图由后台线程生成。
            self.message_label = QLabel()
            self.full_image_data = image_data
            display_name = file_name or text.replace("[图片]", "").strip()
            self.message_label.setText(f"[图片] {display_name}\n点击查看")
            self.message_label.setWordWrap(True)
            self.message_label.setAlignment(Qt.AlignCenter)
            self.message_label.setCursor(Qt.PointingHandCursor)
            self.message_label.mousePressEvent = lambda e: self._show_full_image()
        else:
            # 显示文本消息
            self.message_label = QLabel(text)
            self.message_label.setWordWrap(True)
            self.message_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            self.full_image_data = ""

        # 根据消息类型构建布局（本人/系统/安全/他人）
        if kind == "self":
            # 本人消息：头像在右侧，消息内容在左侧
            self.message_label.setStyleSheet(self._bubble_style("#dbeafe", "#1e3a8a", is_self=True))
            self.message_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
            
            # 带时间戳的消息区域
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
            # 系统消息：居中显示，无头像
            self.message_label.setAlignment(Qt.AlignCenter)
            self.message_label.setStyleSheet(self._bubble_style("#f3f4f6", "#6b7280", is_system=True))
            layout.addStretch(1)
            layout.addWidget(self.message_label, 0)
            layout.addStretch(1)
            self.avatar_label.hide()
            self.username_label.hide()
            self.timestamp_label.hide()
        elif kind == "security":
            # 安全提示：占满宽度，无头像
            self.message_label.setStyleSheet(self._bubble_style("#fffbeb", "#92400e", is_system=True))
            self.message_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
            layout.addWidget(self.message_label, 1)
            self.avatar_label.hide()
            self.username_label.hide()
            self.timestamp_label.hide()
        else:
            # 他人消息：头像在左侧，消息内容在右侧
            self.message_label.setStyleSheet(self._bubble_style("#ffffff", "#1f2937", is_self=False))
            self.message_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
            
            # 带时间戳的消息区域
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

    def set_thumbnail(self, image: QImage) -> None:
        """把后台生成的缩略图应用到图片消息气泡。"""
        if not self.image_data or image.isNull():
            return
        pixmap = QPixmap.fromImage(image)
        if pixmap.isNull():
            return
        self.thumbnail_pixmap = pixmap
        if self.show_cipher and self.ciphertext:
            return
        self.message_label.setPixmap(pixmap)
        self.message_label.setText("")
        self.message_label.setAlignment(Qt.AlignCenter)
        self.message_label.setScaledContents(False)
        self.message_label.setMinimumSize(pixmap.width() + 64, pixmap.height() + 48)
        self.message_label.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.message_label.setCursor(Qt.PointingHandCursor)
        self.message_label.mousePressEvent = lambda e: self._show_full_image()
        self.message_label.updateGeometry()

    def set_image_data(self, image_data: str, file_name: str = "") -> None:
        """设置图片正文数据，供缩略图和原图预览使用。"""
        self.image_data = image_data
        self.full_image_data = image_data
        if file_name:
            self.file_name = file_name

    def set_ciphertext(self, ciphertext: str) -> None:
        self.ciphertext = ciphertext

    def set_display_mode(self, show_ciphertext: bool) -> None:
        self.show_cipher = show_ciphertext
        if show_ciphertext and (self.ciphertext or self.hmac or self.sig):
            self.message_label.setPixmap(QPixmap())
            if self.image_data or self.file_name:
                self.message_label.setCursor(Qt.PointingHandCursor)
                self.message_label.mousePressEvent = lambda e: self._show_full_ciphertext()
            if not self.hmac and not self.sig:
                font = QFont("Consolas")
                font.setPointSize(19)
                self.message_label.setFont(font)
                self.message_label.setText(self._cipher_preview())
            else:
                self.message_label.setText(self._build_security_layers_html())
            return

        if self.image_data or self.file_name:
            self._restore_image_display()
        else:
            self.message_label.setFont(QFont())
            self.message_label.setText(self.text)
            self._restore_style()

    def _restore_image_display(self) -> None:
        self._restore_style()
        self.message_label.setCursor(Qt.PointingHandCursor)
        self.message_label.mousePressEvent = lambda e: self._show_full_image()
        if self.thumbnail_pixmap and not self.thumbnail_pixmap.isNull():
            self.message_label.setPixmap(self.thumbnail_pixmap)
            self.message_label.setText("")
            self.message_label.setAlignment(Qt.AlignCenter)
            return
        display_name = self.file_name or self.text.replace("[图片]", "").strip()
        self.message_label.setPixmap(QPixmap())
        self.message_label.setText(f"[图片] {display_name}\n点击查看")
        self.message_label.setAlignment(Qt.AlignCenter)

    def _cipher_value(self) -> str:
        import ast
        import json

        cipher_val = self.ciphertext or ""
        try:
            s = str(self.ciphertext).strip()
            if s.startswith("{"):
                try:
                    obj = ast.literal_eval(s)
                except Exception:
                    obj = json.loads(s)
                if isinstance(obj, dict) and "ciphertext" in obj:
                    cipher_val = obj.get("ciphertext", "")
        except Exception:
            cipher_val = self.ciphertext
        return str(cipher_val)

    def _has_image_cipher(self) -> bool:
        if not (self.image_data or self.file_name):
            return False
        text = str(self.ciphertext or "")
        return "AES-256-GCM" in text and "ciphertext" in text

    def _cipher_preview(self, limit: int = 1600) -> str:
        if (self.image_data or self.file_name) and not self._has_image_cipher():
            return "图片密文尚未加载。请切回明文点击图片，拉取图片后再查看密文。"
        value = self._cipher_value()
        if len(value) <= limit:
            return value
        return f"{value[:limit]}\n\n... 点击查看完整密文"

    def _build_security_layers_html(self) -> str:
        """构建仅包含 DES ciphertext、HMAC 和 RSA signature 的安全层 HTML。

        规则：
        - 不显示 Plaintext 和 Packet Info
        - 若 ciphertext 是 dict 字符串或 dict，尝试提取内部 'ciphertext' 字段（不显示 iv）
        """
        import html

        html_parts = []
        cipher_display_escaped = html.escape(self._cipher_preview())
        cipher_title = "图片密文" if self._has_image_cipher() else "DES 加密 (ciphertext)"

        # DES 层（蓝色）：只显示 ciphertext（不包含 iv）
        if cipher_display_escaped:
            html_parts.append(f'''
        <div style="background: #dbeafe; border: 1px solid #0284c7; border-radius: 4px; padding: 8px; margin-bottom: 8px;">
            <div style="font-weight: 600; font-size: 22px; color: #075985; margin-bottom: 6px;">{cipher_title}</div>
            <div style="font-size: 21px; color: #0c4a6e; font-family: 'Consolas', monospace; word-wrap: break-word; white-space: pre-wrap; max-height: 260px; overflow-y: auto;">
                {cipher_display_escaped}
            </div>
        </div>
        ''')

        # HMAC 层：始终显示（若为空显示 '(none)'）
        hmac_display = str(self.hmac) if self.hmac else "(none)"
        hmac_display_escaped = html.escape(hmac_display)
        html_parts.append(f'''
        <div style="background: #dbeafe; border: 1px solid #0284c7; border-radius: 4px; padding: 8px; margin-bottom: 8px;">
            <div style="font-weight: 600; font-size: 22px; color: #075985; margin-bottom: 6px;">HMAC-SHA256</div>
            <div style="font-size: 21px; color: #0c4a6e; font-family: 'Consolas', monospace; word-wrap: break-word; white-space: pre-wrap; max-height: 200px; overflow-y: auto;">
                {hmac_display_escaped}
            </div>
        </div>
        ''')

        # RSA 层：始终显示（若为空显示 '(none)'）
        sig_display = str(self.sig) if self.sig else "(none)"
        sig_display_escaped = html.escape(sig_display)
        html_parts.append(f'''
        <div style="background: #dbeafe; border: 1px solid #0284c7; border-radius: 4px; padding: 8px; margin-bottom: 8px;">
            <div style="font-weight: 600; font-size: 22px; color: #075985; margin-bottom: 6px;">RSA Signature</div>
            <div style="font-size: 21px; color: #0c4a6e; font-family: 'Consolas', monospace; word-wrap: break-word; white-space: pre-wrap; max-height: 260px; overflow-y: auto;">
                {sig_display_escaped}
            </div>
        </div>
        ''')

        return ''.join(html_parts)

    def _show_full_ciphertext(self) -> None:
        if not (self.ciphertext or self.hmac or self.sig):
            return
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QPushButton

        dialog = QDialog()
        dialog.setWindowTitle("图片密文")
        dialog.setMinimumSize(1100, 760)

        layout = QVBoxLayout(dialog)
        text = QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(self._full_ciphertext_text())
        font = QFont("Consolas")
        font.setPointSize(18)
        text.setFont(font)
        layout.addWidget(text, 1)

        close_button = QPushButton("关闭")
        close_button.clicked.connect(dialog.accept)
        layout.addWidget(close_button)
        dialog.showMaximized()
        dialog.exec_()

    def _full_ciphertext_text(self) -> str:
        parts = []
        if self.ciphertext:
            if self.image_data or self.file_name:
                title = "图片密文"
                value = self._cipher_value() if self._has_image_cipher() else "图片密文尚未加载。请切回明文点击图片，拉取图片后再查看密文。"
            else:
                title = "消息密文"
                value = self._cipher_value()
            parts.append(f"{title}\n{value}")
        if self.hmac:
            parts.append(f"HMAC-SHA256\n{self.hmac}")
        if self.sig:
            parts.append(f"RSA Signature\n{self.sig}")
        return "\n\n".join(parts)

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
        """点击图片时弹出对话框查看原始大图。"""
        from PyQt5.QtWidgets import QFileDialog, QDialog, QHBoxLayout, QVBoxLayout, QScrollArea, QLabel, QPushButton
        from PyQt5.QtGui import QPixmap
        
        if not getattr(self, 'full_image_data', ''):
            return
        try:
            image_bytes = base64.b64decode(self.full_image_data, validate=True)
        except Exception:
            return
        
        dialog = QDialog()
        dialog.setWindowTitle(self.file_name if getattr(self, 'file_name', '') else "查看图片")
        dialog.setMinimumSize(900, 620)
        layout = QVBoxLayout(dialog)
        
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        
        pixmap = QPixmap()
        if not pixmap.loadFromData(image_bytes):
            return
        
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
    """紧凑的键值状态行组件。

    用于在右侧面板显示简短状态项（例如：认证、连接、心跳等）。
    """

    clicked = pyqtSignal(str)

    def __init__(self, name: str, value: str, badge: str = "mutedBadge") -> None:
        super().__init__()
        self.name = name
        self._value = value
        self.name_label = QLabel(name)
        self.name_label.setObjectName("hint")
        self.value_label = QLabel(value)
        self.value_label.setObjectName(badge)
        self.setCursor(Qt.PointingHandCursor)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.name_label)
        layout.addStretch(1)
        layout.addWidget(self.value_label)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self.name)
        super().mousePressEvent(event)

    def set_value(self, value: str, badge: str = "mutedBadge") -> None:
        self._value = value
        self.value_label.setText(value)
        self.value_label.setObjectName(badge)
        self.value_label.style().unpolish(self.value_label)
        self.value_label.style().polish(self.value_label)

    def current_value(self) -> str:
        return self._value


class ChatView(QWidget):
    """三栏式聊天工作区视图。

    左侧为用户与会话列表，中间为消息流与输入，右侧为状态信息与安全提示。
    """

    message_send_requested = pyqtSignal(str)
    session_changed = pyqtSignal()
    return_to_group_chat_requested = pyqtSignal()
    relogin_requested = pyqtSignal()
    image_send_requested = pyqtSignal()
    image_open_requested = pyqtSignal(object)
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
        self.message_scroll: QScrollArea | None = None
        self.message_input = QTextEdit()
        self.send_button = QPushButton("发送")
        self.toggle_cipher_button = QPushButton("显示密文")
        self.show_ciphertext = False
        self.message_bubbles: list[MessageBubble] = []
        self._has_cipher_messages_cache = False
        self._message_batch_depth = 0
        self._pending_cipher_refresh = False
        self._thumbnail_cache: OrderedDict[str, QImage] = OrderedDict()
        self._thumbnail_waiting: dict[str, list[MessageBubble]] = {}
        self._thumbnail_worker = ThumbnailWorker(self)
        self._thumbnail_worker.thumbnail_ready.connect(self._on_thumbnail_ready)
        self._thumbnail_worker.thumbnail_failed.connect(self._on_thumbnail_failed)
        self._thumbnail_worker.start()
        self.is_admin_user = False
        
        # 跟踪当前会话类型和接收者
        self.current_chat_type = "group"
        self.current_recipient = ""
        self._session_key_plaintext = ""
        self._session_key_visible = False

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
        self.key_status.clicked.connect(self._toggle_session_key_display)
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

        self.message_scroll = QScrollArea()
        self.message_scroll.setWidgetResizable(True)
        self.message_scroll.setFrameShape(QFrame.NoFrame)
        self.message_scroll.setWidget(scroll_content)
        layout.addWidget(self.message_scroll, 1)

        self.message_input.setPlaceholderText("输入消息")
        self.message_input.setFixedHeight(76)
        self.message_input.textChanged.connect(self._update_send_button_state)
        layout.addWidget(self.message_input)

        # 上传进度条与说明标签
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
        
        # 初始化发送按钮状态
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

    def add_message(self, text: str, kind: str = "peer", ciphertext: str = "", image_data: str = "", file_name: str = "", username: str = "", timestamp: str = "", hmac: str = "", sig: str = "", pubkey: str = "") -> MessageBubble:
        bubble = MessageBubble(text, kind, ciphertext, image_data, file_name, username, timestamp, hmac, sig, pubkey)
        self.message_area.insertWidget(self.message_area.count() - 1, bubble)
        if kind not in ("system", "security"):
            self.message_bubbles.append(bubble)
            if ciphertext or hmac or sig:
                self._has_cipher_messages_cache = True
            bubble.set_display_mode(self.show_ciphertext)
            if image_data:
                self._request_thumbnail(bubble, image_data, file_name)
            if image_data or file_name:
                bubble.message_label.mousePressEvent = lambda event, item=bubble: self._handle_image_click(item)
        if self._message_batch_depth:
            self._pending_cipher_refresh = True
        else:
            self._refresh_cipher_toggle_ui()
        return bubble

    def set_message_image(self, bubble: MessageBubble, image_data: str, file_name: str = "", ciphertext: str = "") -> None:
        """给已有图片消息气泡填充图片正文并生成缩略图。"""
        if bubble not in self.message_bubbles:
            return
        bubble.set_image_data(image_data, file_name)
        if ciphertext:
            bubble.set_ciphertext(ciphertext)
        self._request_thumbnail(bubble, image_data, file_name or bubble.file_name)
        bubble.set_display_mode(self.show_ciphertext)

    def _request_thumbnail(self, bubble: MessageBubble, image_data: str, file_name: str) -> None:
        key = self._thumbnail_key(image_data, file_name)
        cached = self._thumbnail_cache.get(key)
        if cached is not None:
            self._thumbnail_cache.move_to_end(key)
            bubble.set_thumbnail(cached)
            return
        waiters = self._thumbnail_waiting.setdefault(key, [])
        waiters.append(bubble)
        if len(waiters) == 1:
            self._thumbnail_worker.enqueue(key, image_data)

    def _handle_image_click(self, bubble: MessageBubble) -> None:
        if getattr(bubble, "show_cipher", False) and (getattr(bubble, "ciphertext", "") or getattr(bubble, "hmac", "") or getattr(bubble, "sig", "")):
            bubble._show_full_ciphertext()
            return
        if getattr(bubble, "full_image_data", ""):
            bubble._show_full_image()
            return
        self.image_open_requested.emit(bubble)

    @staticmethod
    def _thumbnail_key(image_data: str, file_name: str) -> str:
        digest = hashlib.sha256(image_data.encode("utf-8", errors="ignore")).hexdigest()
        return f"{file_name}:{len(image_data)}:{digest}"

    def _on_thumbnail_ready(self, key: str, image: QImage) -> None:
        self._remember_thumbnail(key, image)
        for bubble in self._thumbnail_waiting.pop(key, []):
            if bubble in self.message_bubbles:
                bubble.set_thumbnail(image)

    def _on_thumbnail_failed(self, key: str) -> None:
        self._thumbnail_waiting.pop(key, None)

    def _remember_thumbnail(self, key: str, image: QImage) -> None:
        self._thumbnail_cache[key] = image
        self._thumbnail_cache.move_to_end(key)
        while len(self._thumbnail_cache) > 80:
            self._thumbnail_cache.popitem(last=False)

    def clear_messages(self) -> None:
        """移除界面上所有显示的消息气泡。"""
        while self.message_area.count() > 1:
            item = self.message_area.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        self.message_bubbles.clear()
        self._thumbnail_waiting.clear()
        self._has_cipher_messages_cache = False
        if self._message_batch_depth:
            self._pending_cipher_refresh = True
        else:
            self._refresh_cipher_toggle_ui()

    def begin_message_batch(self, scroll_to_latest: bool = False) -> None:
        """开始批量更新消息，暂停重绘以减少 UI 卡顿。"""
        self._message_batch_depth += 1
        if scroll_to_latest:
            self._pending_scroll_to_latest = True
        if self._message_batch_depth == 1:
            self.setUpdatesEnabled(False)

    def end_message_batch(self) -> None:
        """结束批量更新消息，恢复重绘并刷新按钮状态。"""
        if self._message_batch_depth <= 0:
            return
        self._message_batch_depth -= 1
        if self._message_batch_depth == 0:
            self.setUpdatesEnabled(True)
            if self._pending_cipher_refresh:
                self._pending_cipher_refresh = False
                self._refresh_cipher_toggle_ui()
            self.update()
            if getattr(self, "_pending_scroll_to_latest", False):
                self._pending_scroll_to_latest = False
                QTimer.singleShot(0, self.scroll_to_latest)

    def scroll_to_latest(self) -> None:
        """滚动到最新消息。"""
        if not self.message_scroll:
            return
        bar = self.message_scroll.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _toggle_cipher_display(self) -> None:
        if not self._has_cipher_messages():
            return
        self.show_ciphertext = not self.show_ciphertext
        for bubble in self.message_bubbles:
            bubble.set_display_mode(self.show_ciphertext)
        self._refresh_cipher_toggle_ui()

    def _has_cipher_messages(self) -> bool:
        return self._has_cipher_messages_cache

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

    def closeEvent(self, event) -> None:
        self.shutdown()
        super().closeEvent(event)

    def shutdown(self) -> None:
        """停止聊天视图持有的后台线程。"""
        self._thumbnail_worker.stop()

    def current_session(self) -> dict[str, str]:
        """返回当前选中的会话路由信息（群聊或私聊）。"""
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
        """设置当前会话类型和接收者，并更新标题显示。"""
        self.current_chat_type = chat_type
        self.current_recipient = recipient
        self.chat_title_label.setText(f"私聊 {recipient}" if chat_type == "private" and recipient else "群聊大厅")

    def set_session_key(self, session_key: str) -> None:
        """设置当前会话密钥并默认隐藏明文。"""
        self._session_key_plaintext = session_key or ""
        self._session_key_visible = False
        self._refresh_session_key_label()

    def _toggle_session_key_display(self, _name: str) -> None:
        if not self._session_key_plaintext:
            return
        self._session_key_visible = not self._session_key_visible
        self._refresh_session_key_label()

    def _refresh_session_key_label(self) -> None:
        if not self._session_key_plaintext:
            self.key_status.set_value("未建立", "warnBadge")
            return
        if self._session_key_visible:
            self.key_status.set_value(self._session_key_plaintext, "okBadge")
            self.key_status.value_label.setToolTip("点击可隐藏会话密钥")
        else:
            masked = f"{self._session_key_plaintext[:6]}...{self._session_key_plaintext[-4:]}" if len(self._session_key_plaintext) > 12 else "已建立"
            self.key_status.set_value(masked, "okBadge")
            self.key_status.value_label.setToolTip("点击可显示会话密钥")

    def set_online_users(self, users: list[dict]) -> None:
        """用服务器返回的用户列表替换左侧在线用户视图。

        函数会根据用户角色、在线状态和是否被禁言构建显示后缀，并在当前用户处禁用点击。
        """
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
        """根据输入内容更新发送按钮的可用/样式状态。"""
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
        """显示上传进度条并初始化为准备状态。"""
        self.upload_progress.setVisible(True)
        self.upload_progress.setValue(0)
        self.upload_progress_label.setVisible(True)
        self.upload_progress_label.setText("正在准备上传...")

    def set_upload_progress(self, value: int, text: str = "") -> None:
        """设置上传进度值（0-100）及可选的状态文本显示。"""
        self.upload_progress.setValue(value)
        if text:
            self.upload_progress_label.setText(text)

    def hide_upload_progress(self) -> None:
        """隐藏上传进度条和说明标签。"""
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
