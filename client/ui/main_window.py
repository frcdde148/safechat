"""SafeChat client main window."""

from __future__ import annotations

from PyQt5.QtCore import QThread, QTimer
from PyQt5.QtWidgets import QMainWindow, QStackedWidget, QMessageBox

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
        self._image_send_threads: list[QThread] = []
        self._is_relogin = False
        self._stage_timer = QTimer(self)
        self._stage_timer.setInterval(1100)
        self._stage_timer.timeout.connect(self._advance_demo_auth)
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(1500)
        self._poll_timer.timeout.connect(self._poll_chat_messages)
        self.login_view.login_requested.connect(self._start_demo_auth)
        self.login_view.enter_chat_requested.connect(self._enter_chat)
        self.chat_view.message_send_requested.connect(self._send_chat_message)
        self.chat_view.session_changed.connect(self._switch_chat_session)
        self.chat_view.private_chat_requested.connect(self._open_private_chat)
        self.chat_view.return_to_group_chat_requested.connect(self._return_to_group_chat)
        self.chat_view.relogin_requested.connect(self._handle_relogin)
        self.chat_view.image_send_requested.connect(self._send_image)
        self.chat_view.mute_user_requested.connect(self._mute_user)
        self.chat_view.unmute_user_requested.connect(self._unmute_user)

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
            
            if getattr(self, '_is_relogin', False):
                # Handle re-login completion
                self._is_relogin = False
                try:
                    self._enter_chat()
                    self.chat_view.add_message("系统提示：重新认证成功，票据和会话密钥已刷新", "system")
                    self.chat_view.security_status.set_value("重新认证成功", "okBadge")
                except Exception as exc:
                    self.chat_view.add_message(f"安全提示：重新认证后进入聊天室失败，{exc}", "security")
                    self.chat_view.security_status.set_value("进入聊天室失败", "errorBadge")
                finally:
                    self.chat_view.relogin_button.setEnabled(True)
                    self.chat_view.relogin_button.setObjectName("secondaryButton")
                    self.chat_view.relogin_button.style().unpolish(self.chat_view.relogin_button)
                    self.chat_view.relogin_button.style().polish(self.chat_view.relogin_button)
                return
            
            # Normal login completion
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
            if getattr(self, '_is_relogin', False):
                self._is_relogin = False
                self.chat_view.relogin_button.setEnabled(True)
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
            
            if getattr(self, '_is_relogin', False):
                self._is_relogin = False
                self.chat_view.add_message(f"安全提示：重新认证失败，{detail}", "security")
                self.chat_view.security_status.set_value("重新认证失败", "errorBadge")
                self.chat_view.relogin_button.setEnabled(True)
            return
        self._stage_index += 1

    def _enter_chat(self) -> None:
        username = self._auth_payload.get("username", self.login_view.username_input.text().strip())
        chat_host = self._auth_client.chat_host if self._auth_client else ""
        chat_port = self._auth_client.chat_port if self._auth_client else 0
        self.chat_view.current_user_label.setText(username)
        self.chat_view.server_status.set_value(f"{chat_host}:{chat_port}", "okBadge")
        self.chat_view.heartbeat_status.set_value("刚刚", "okBadge")
        self.stack.setCurrentWidget(self.chat_view)
        
        # Display offline messages if any
        if self._auth_client:
            offline_messages = self._auth_client.get_offline_messages()
            for msg in offline_messages:
                self.chat_view.add_message(f"{msg['sender']}：{msg['text']}", "other", msg.get("ciphertext"))
        
        self._refresh_online_users()
        self._poll_timer.start()

    def _send_chat_message(self, text: str) -> None:
        if not self._auth_client:
            self.chat_view.add_message("系统提示：尚未完成认证，不能发送消息", "security")
            self.chat_view.security_status.set_value("未认证", "errorBadge")
            return

        # Prevent duplicate sends
        if getattr(self, '_is_sending', False):
            return
        self._is_sending = True
        
        self.chat_view.send_button.setEnabled(False)
        session = self.chat_view.current_session()
        
        try:
            result = self._auth_client.send_chat_message(
                text,
                session["chat_type"],
                session["recipient"],
            )
            self.chat_view.message_input.clear()
            
            from datetime import datetime
            timestamp = datetime.now().strftime("%H:%M:%S")
            ciphertext = str(result.get("sent", {}).get("body", {}).get("message_cipher", ""))

            self.chat_view.add_message(text, "self", ciphertext, "", "", self._auth_client.username, timestamp)
            ack = result.get("ack", "")
            if ack:
                if "对方离线" in ack or "已存储" in ack:
                    self.chat_view.security_status.set_value("对方离线，消息已存储", "warnBadge")
                else:
                    self.chat_view.security_status.set_value("消息已加密送达", "okBadge")
            else:
                self.chat_view.security_status.set_value("回执为空", "warnBadge")
        except Exception as exc:
            self.chat_view.add_message(f"安全提示：消息发送失败，{exc}", "security")
            self.chat_view.security_status.set_value("发送失败", "errorBadge")
        finally:
            self._is_sending = False
            self.chat_view.send_button.setEnabled(True)
            self.chat_view.heartbeat_status.set_value("刚刚", "okBadge")

    def _poll_chat_messages(self) -> None:
        if not self._auth_client or self.stack.currentWidget() is not self.chat_view:
            return
        
        if getattr(self, '_poll_thread', None) and self._poll_thread.isRunning():
            return
        
        from PyQt5.QtCore import QThread, pyqtSignal
        
        class PollThread(QThread):
            finished = pyqtSignal(list)
            error = pyqtSignal(Exception)
            
            def __init__(self, auth_client, chat_type, recipient):
                super().__init__()
                self.auth_client = auth_client
                self.chat_type = chat_type
                self.recipient = recipient
            
            def run(self):
                try:
                    messages = self.auth_client.poll_chat_messages(self.chat_type, self.recipient)
                    self.finished.emit(messages)
                except Exception as exc:
                    self.error.emit(exc)
        
        session = self.chat_view.current_session()
        self._poll_thread = PollThread(self._auth_client, session["chat_type"], session["recipient"])
        self._poll_thread.finished.connect(self._on_poll_finished)
        self._poll_thread.error.connect(self._on_poll_error)
        self._poll_thread.start()
    
    def _on_poll_finished(self, messages):
        self._display_chat_messages(messages, include_self=True)
        if messages:
            self.chat_view.heartbeat_status.set_value("刚刚", "okBadge")
            self.chat_view.security_status.set_value("群聊同步正常", "okBadge")
        self._refresh_online_users()
        self._poll_thread = None

    @staticmethod
    def _is_ticket_expired_error(exc: Exception) -> bool:
        message = str(exc).lower()
        return "expired" in message and ("ticket" in message or "tgt" in message)

    def _mark_reauth_required(self, reason: str) -> None:
        self.chat_view.security_status.set_value("票据已过期，请重新认证", "errorBadge")
        self.chat_view.heartbeat_status.set_value("已停止", "errorBadge")
        self.chat_view.relogin_button.setEnabled(True)
        self.chat_view.relogin_button.setObjectName("primaryButton")
        self.chat_view.relogin_button.style().unpolish(self.chat_view.relogin_button)
        self.chat_view.relogin_button.style().polish(self.chat_view.relogin_button)
        self.chat_view.add_message(f"安全提示：Kerberos 票据已失效，请点击“重新认证”。{reason}", "security")
    
    def _on_poll_error(self, exc):
        if self._is_ticket_expired_error(exc):
            self._mark_reauth_required(str(exc))
            self._poll_timer.stop()
            self._poll_thread = None
            return
        self.chat_view.security_status.set_value("轮询失败", "errorBadge")
        self.chat_view.add_message(f"安全提示：拉取群聊消息失败，{exc}", "security")
        self._poll_timer.stop()
        self._poll_thread = None

    def _refresh_online_users(self) -> None:
        if not self._auth_client:
            return
        try:
            users = self._auth_client.fetch_online_users()
        except Exception as exc:
            if self._is_ticket_expired_error(exc):
                self._mark_reauth_required(str(exc))
                self._poll_timer.stop()
                return
            self.chat_view.security_status.set_value("用户列表异常", "errorBadge")
            self.chat_view.add_message(f"安全提示：刷新在线用户失败，{exc}", "security")
            return
        self.chat_view.set_online_users(users)

    def _switch_chat_session(self) -> None:
        self.chat_view.clear_messages()
        session = self.chat_view.current_session()
        self.chat_view.session_type_status.set_value(session["title"], "okBadge")
        self.chat_view.add_message(f"系统通知：已切换到 {session['title']}", "system")
        if not self._auth_client:
            return
        self._auth_client.reset_session_cursor(session["chat_type"], session["recipient"])
        try:
            messages = self._auth_client.poll_chat_messages(session["chat_type"], session["recipient"])
        except Exception as exc:
            if self._is_ticket_expired_error(exc):
                self._mark_reauth_required(str(exc))
                self._poll_timer.stop()
                return
            self.chat_view.security_status.set_value("轮询失败", "errorBadge")
            self.chat_view.add_message(f"安全提示：拉取会话消息失败，{exc}", "security")
            return
        self._display_chat_messages(messages, include_self=True)

    def _display_chat_messages(self, messages: list[dict], include_self: bool = False) -> None:
        if not self._auth_client:
            return
        from datetime import datetime
        for message in messages:
            is_self = message["sender"] == self._auth_client.username
            if is_self and not include_self:
                continue
            kind = "self" if is_self else "peer"
            ciphertext = message.get("ciphertext", "")
            image_data = message.get("image_data", "")
            file_name = message.get("file_name", "")
            username = message["sender"] if not is_self else self._auth_client.username
            
            # Convert timestamp from milliseconds to readable format
            timestamp = message.get("timestamp", "")
            if timestamp:
                try:
                    ts = int(timestamp) / 1000  # Convert ms to seconds
                    timestamp = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
                except:
                    timestamp = ""
                    
            self.chat_view.add_message(message['text'], kind, ciphertext, image_data, file_name, username, timestamp)

    def _open_private_chat(self, username: str) -> None:
        """Open a private chat with the selected contact."""
        if not self._auth_client:
            return
        if username == self._auth_client.username:
            QMessageBox.warning(self, "警告", "不能与自己发起私聊")
            return
        
        # Set current session to private chat
        self.chat_view.set_current_session("private", username)
        
        # Clear messages and switch to private chat
        self.chat_view.clear_messages()
        self.chat_view.session_type_status.set_value(f"私聊 {username}", "okBadge")
        self.chat_view.add_message(f"系统通知：已切换到私聊 {username}", "system")
        
        if not self._auth_client:
            return
        
        self._auth_client.reset_session_cursor("private", username)
        try:
            messages = self._auth_client.poll_chat_messages("private", username)
        except Exception as exc:
            if self._is_ticket_expired_error(exc):
                self._mark_reauth_required(str(exc))
                self._poll_timer.stop()
                return
            self.chat_view.security_status.set_value("轮询失败", "errorBadge")
            self.chat_view.add_message(f"安全提示：拉取私聊消息失败，{exc}", "security")
            return
        self._display_chat_messages(messages, include_self=True)

    def _return_to_group_chat(self) -> None:
        """Return to group chat from private chat."""
        # Set current session to group chat
        self.chat_view.set_current_session("group", "")
        
        self.chat_view.clear_messages()
        self.chat_view.session_type_status.set_value("群聊大厅", "okBadge")
        self.chat_view.add_message("系统通知：已切换到群聊大厅", "system")
        if not self._auth_client:
            return
        self._auth_client.reset_session_cursor("group", "")
        try:
            messages = self._auth_client.poll_chat_messages("group", "")
        except Exception as exc:
            if self._is_ticket_expired_error(exc):
                self._mark_reauth_required(str(exc))
                self._poll_timer.stop()
                return
            self.chat_view.security_status.set_value("轮询失败", "errorBadge")
            self.chat_view.add_message(f"安全提示：拉取群聊消息失败，{exc}", "security")
            return
        self._display_chat_messages(messages, include_self=True)

    def _handle_relogin(self) -> None:
        """Refresh Kerberos tickets and chat session keys."""
        if not self._auth_client or not self._auth_payload:
            self.chat_view.add_message("系统提示：无法重新认证，请返回登录页", "security")
            return
        
        self.chat_view.add_message("系统提示：正在重新认证...", "system")
        self.chat_view.relogin_button.setEnabled(False)
        self.chat_view.relogin_button.setObjectName("secondaryButton")
        self.chat_view.relogin_button.style().unpolish(self.chat_view.relogin_button)
        self.chat_view.relogin_button.style().polish(self.chat_view.relogin_button)
        
        try:
            self._auth_client.reset_session()
            self._stage_index = 0
            self._is_relogin = True
            self._stage_timer.start()
        except Exception as exc:
            self.chat_view.add_message(f"安全提示：重新认证失败，{exc}", "security")
            self.chat_view.security_status.set_value("重新认证失败", "errorBadge")
            self.chat_view.relogin_button.setEnabled(True)

    def _mute_user(self, username: str) -> None:
        """Mute a user from the admin contact menu."""
        if not self._auth_client:
            return
        try:
            result = self._auth_client.admin_mute_user(username, duration_seconds=600, reason="管理员客户端禁言")
        except Exception as exc:
            self.chat_view.add_message(f"安全提示：禁言 {username} 失败，{exc}", "security")
            self.chat_view.security_status.set_value("禁言失败", "errorBadge")
            return
        expires_at = result.get("expires_at", 0)
        self.chat_view.add_message(f"系统通知：已禁言 {username} 10 分钟，expires_at={expires_at}", "system")
        self.chat_view.security_status.set_value("禁言规则已生效", "okBadge")
        self._refresh_online_users()

    def _unmute_user(self, username: str) -> None:
        """Unmute a user from the admin contact menu."""
        if not self._auth_client:
            return
        try:
            self._auth_client.admin_unmute_user(username)
        except Exception as exc:
            self.chat_view.add_message(f"安全提示：解除 {username} 禁言失败，{exc}", "security")
            self.chat_view.security_status.set_value("解除禁言失败", "errorBadge")
            return
        self.chat_view.add_message(f"系统通知：已解除 {username} 的禁言", "system")
        self.chat_view.security_status.set_value("禁言已解除", "okBadge")
        self._refresh_online_users()

    def _send_image(self) -> None:
        """Handle image send request."""
        from PyQt5.QtWidgets import QFileDialog
        import os
        
        if not self._auth_client:
            self.chat_view.add_message("系统提示：尚未完成认证，不能发送图片", "security")
            return
        
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "选择图片", 
            "", 
            "图片文件 (*.png *.jpg *.jpeg *.gif *.bmp)"
        )
        
        if not file_path:
            return
        
        # Show progress bar
        self.chat_view.show_upload_progress()
        self.chat_view.set_upload_progress(10)
        
        # Execute image send in a separate thread to avoid blocking UI
        from PyQt5.QtCore import QThread, pyqtSignal
        
        class ImageSendThread(QThread):
            finished = pyqtSignal(dict)
            error = pyqtSignal(Exception)
            progress = pyqtSignal(int, str)
            preview_ready = pyqtSignal(str, str)
            
            def __init__(self, auth_client, file_path, chat_type, recipient):
                super().__init__()
                self.auth_client = auth_client
                self.file_path = file_path
                self.chat_type = chat_type
                self.recipient = recipient
            
            def run(self):
                try:
                    def progress_callback(value, text=""):
                        self.progress.emit(value, text)
                    result = self.auth_client.send_image(
                        self.file_path,
                        progress_callback=progress_callback,
                        chat_type=self.chat_type,
                        recipient=self.recipient,
                        preview_callback=self.preview_ready.emit,
                    )
                    self.finished.emit(result)
                except Exception as exc:
                    self.error.emit(exc)

        def on_preview_ready(file_name, image_base64):
            current = self.chat_view.current_session()
            if current["chat_type"] != session["chat_type"] or current["recipient"] != session["recipient"]:
                return
            from datetime import datetime
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.chat_view.add_message(
                f"[图片] {file_name}（后台发送中）",
                "self",
                "",
                image_base64,
                file_name,
                self._auth_client.username,
                timestamp,
            )
        
        def on_send_finished(result):
            try:
                self.chat_view.set_upload_progress(80, "正在处理响应...")
                
                if result.get("success"):
                    self.chat_view.set_upload_progress(100, "上传完成！")
                    self.chat_view.add_message(f"图片发送成功：{result.get('file_name')}", "system")
                    self.chat_view.security_status.set_value("图片已发送", "okBadge")
                else:
                    self.chat_view.set_upload_progress(0, "上传失败")
                    self.chat_view.add_message(f"图片发送失败：{result.get('error', '未知错误')}", "security")
            finally:
                self.chat_view.hide_upload_progress()
                self.chat_view.image_button.setEnabled(True)
                if thread in self._image_send_threads:
                    self._image_send_threads.remove(thread)
        
        def on_send_error(exc):
            try:
                self.chat_view.set_upload_progress(0, "发送失败")
                self.chat_view.add_message(f"安全提示：图片发送失败，{exc}", "security")
                self.chat_view.security_status.set_value("发送失败", "errorBadge")
            finally:
                self.chat_view.hide_upload_progress()
                self.chat_view.image_button.setEnabled(True)
                if thread in self._image_send_threads:
                    self._image_send_threads.remove(thread)
        
        # Start the thread
        self.chat_view.set_upload_progress(30, "正在初始化...")
        self.chat_view.image_button.setEnabled(False)
        session = self.chat_view.current_session()
        thread = ImageSendThread(
            self._auth_client,
            file_path,
            session["chat_type"],
            session["recipient"],
        )
        thread.finished.connect(on_send_finished)
        thread.error.connect(on_send_error)
        thread.progress.connect(self.chat_view.set_upload_progress)
        thread.preview_ready.connect(on_preview_ready)
        self._image_send_threads.append(thread)
        thread.start()
