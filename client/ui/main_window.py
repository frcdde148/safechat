"""SafeChat 客户端主窗口

管理登录视图和聊天视图的切换，协调认证流程和消息收发。
"""

from __future__ import annotations

import time
from collections import OrderedDict

from PyQt5.QtCore import QThread, QTimer, pyqtSignal
from PyQt5.QtWidgets import QMainWindow, QStackedWidget, QMessageBox

from client.net.auth_client import AuthClient
from client.ui.auth_flow_view import AUTH_STAGES
from client.ui.chat_view import ChatView
from client.ui.login_view import LoginView
from client.ui.styles import APP_STYLE


class MainWindow(QMainWindow):
    """客户端主窗口 - 管理登录和聊天视图的切换"""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SafeChat Client")
        self.resize(1680, 980)
        self.setMinimumSize(1360, 820)
        self.setStyleSheet(APP_STYLE)

        # 视图栈（登录/聊天切换）
        self.stack = QStackedWidget()
        self.login_view = LoginView()
        self.chat_view = ChatView()
        self.stack.addWidget(self.login_view)
        self.stack.addWidget(self.chat_view)
        self.setCentralWidget(self.stack)

        # 认证状态
        self._stage_index = 0                    # 当前认证阶段索引
        self._auth_payload: dict = {}             # 认证参数（用户名、密码、服务器地址）
        self._auth_client: AuthClient | None = None  # 认证客户端实例
        self._image_send_threads: list[QThread] = []  # 图片发送线程列表
        self._image_fetch_threads: list[QThread] = []  # 图片历史加载线程列表
        self._image_fetch_inflight: set[int] = set()   # 正在拉取的图片消息ID
        self._session_load_threads: list[QThread] = []  # 会话切换加载线程列表
        self._session_load_generation = 0             # 会话加载版本号（忽略过期结果）
        self._image_data_cache: OrderedDict[int, tuple[str, str]] = OrderedDict()  # 已解密图片缓存
        self._visible_message_ids: set[tuple[str, int]] = set()  # 已显示的消息ID
        self._user_refresh_thread: QThread | None = None  # 在线用户刷新线程
        self._last_user_refresh_at = 0.0              # 在线用户最近刷新时间
        self._last_user_refresh_error_at = 0.0        # 在线用户刷新错误提示时间
        self._is_relogin = False                  # 是否正在重新认证

        # 定时器
        self._stage_timer = QTimer(self)          # 认证阶段定时器
        self._stage_timer.setInterval(1100)       # 每个阶段间隔1.1秒
        self._stage_timer.timeout.connect(self._advance_demo_auth)
        
        self._poll_timer = QTimer(self)           # 消息轮询定时器
        self._poll_timer.setInterval(1500)        # 每1.5秒轮询一次
        self._poll_timer.timeout.connect(self._poll_chat_messages)

        # 信号连接
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
        """开始Kerberos六步认证流程
        
        参数:
            payload: 包含用户名、密码、AS服务器地址的字典
        """
        self.login_view.enter_chat_button.setEnabled(False)
        
        # 验证输入
        if not payload["username"]:
            self.login_view.set_status("请输入用户名", "error")
            return
        if not payload["password"]:
            self.login_view.set_status("请输入密码", "error")
            return

        # 初始化认证流程
        self.login_view.login_button.setEnabled(False)
        self.login_view.auth_flow.reset()
        self.login_view.set_status("认证中", "warn")
        self._auth_payload = payload
        self._auth_client = AuthClient(payload)
        self._stage_index = 0
        self._stage_timer.start()

    def _advance_demo_auth(self) -> None:
        """推进认证阶段（每1.1秒执行一个阶段）"""
        
        # 标记上一个阶段成功
        if self._stage_index > 0:
            previous_stage = AUTH_STAGES[self._stage_index - 1][0]
            self.login_view.auth_flow.mark_success(previous_stage)

        # 检查是否完成所有阶段
        if self._stage_index >= len(AUTH_STAGES):
            self._stage_timer.stop()
            
            # 重新认证完成
            if getattr(self, '_is_relogin', False):
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
            
            # 正常登录完成
            self.login_view.set_status("认证通过", "ok")
            self.login_view.login_button.setEnabled(True)
            self.login_view.enter_chat_button.setEnabled(True)
            self.login_view.auth_flow.append_message(
                "认证完成",
                "已获得 ChatServer 服务票据和会话密钥 Kc,v。可继续查看上方报文细节，确认后点击“进入聊天室”。",
            )
            return

        # 检查认证客户端是否初始化
        if not self._auth_client:
            self._stage_timer.stop()
            self.login_view.set_status("认证客户端未初始化", "error")
            if getattr(self, '_is_relogin', False):
                self._is_relogin = False
                self.chat_view.relogin_button.setEnabled(True)
            return

        # 执行当前认证阶段
        current_stage, current_label = AUTH_STAGES[self._stage_index]
        self.login_view.auth_flow.mark_running(current_stage)
        ok, detail = self._auth_client.run_stage(current_stage)
        self.login_view.auth_flow.append_detail(current_stage, current_label, detail)
        
        # 处理认证失败
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
        
        # 进入下一个阶段
        self._stage_index += 1

    def _enter_chat(self) -> None:
        """进入聊天室
        
        设置聊天视图的初始状态，显示离线消息，启动消息轮询
        """
        username = self._auth_payload.get("username", self.login_view.username_input.text().strip())
        chat_host = self._auth_client.chat_host if self._auth_client else ""
        chat_port = self._auth_client.chat_port if self._auth_client else 0
        
        # 设置用户信息和服务器状态
        self.chat_view.current_user_label.setText(username)
        self.chat_view.server_status.set_value(f"{chat_host}:{chat_port}", "okBadge")
        if self._auth_client:
            self.chat_view.set_session_key(self._auth_client.session_key_c_v)
        self.chat_view.heartbeat_status.set_value("刚刚", "okBadge")
        
        # 切换到聊天视图
        self.stack.setCurrentWidget(self.chat_view)
        
        # 显示离线消息（认证期间收到的消息）
        if self._auth_client:
            offline_messages = self._auth_client.get_offline_messages()
            for msg in offline_messages:
                self.chat_view.add_message(
                    msg["text"],
                    "peer",
                    msg.get("ciphertext", ""),
                    username=msg.get("sender", ""),
                )
        
        # 刷新在线用户列表
        self._refresh_online_users()
        
        # 启动消息轮询
        self._poll_timer.start()

    def _send_chat_message(self, text: str) -> None:
        """发送聊天消息
        
        参数:
            text: 消息文本内容
        """
        if not self._auth_client:
            self.chat_view.add_message("系统提示：尚未完成认证，不能发送消息", "security")
            self.chat_view.security_status.set_value("未认证", "errorBadge")
            return

        # 防止重复发送
        if getattr(self, '_is_sending', False):
            return
        self._is_sending = True
        
        self.chat_view.send_button.setEnabled(False)
        session = self.chat_view.current_session()
        
        try:
            # 调用认证客户端发送消息
            result = self._auth_client.send_chat_message(
                text,
                session["chat_type"],
                session["recipient"],
            )
            self.chat_view.message_input.clear()
            
            from datetime import datetime
            timestamp = datetime.now().strftime("%H:%M:%S")
            sent_msg = result.get("sent", {})
            ciphertext = str(sent_msg.get("body", {}).get("message_cipher", ""))
            hmac_digest = str(sent_msg.get("hmac", ""))
            signature = str(sent_msg.get("sig", ""))
            pubkey = self._auth_client.public_key_pem
            message_id = int(result.get("message_id", 0))
            
            # 记录已发送的消息ID（避免重复显示）
            if message_id:
                self._visible_message_ids.add((self._view_session_key(session["chat_type"], session["recipient"]), message_id))

            # 显示发送的消息（包含安全层信息）
            self.chat_view.add_message(text, "self", ciphertext, "", "", self._auth_client.username, timestamp, hmac_digest, signature, pubkey)
            
            # 处理服务器回执
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
        """轮询聊天消息（每1.5秒执行一次）
        
        流程:
        1. 发送AS心跳保持会话活跃
        2. 检查是否已有轮询线程在运行
        3. 创建异步线程拉取消息
        """
        if not self._auth_client or self.stack.currentWidget() is not self.chat_view:
            return
        
        # 发送AS心跳（保持会话活跃）
        try:
            self._auth_client.heartbeat_as_session()
        except Exception as exc:
            if self._is_ticket_expired_error(exc) or "session is not active" in str(exc).lower():
                self._mark_reauth_required(str(exc))
                self._poll_timer.stop()
                return
        
        # 避免重复轮询
        if any(thread.isRunning() for thread in self._session_load_threads):
            return
        if getattr(self, '_poll_thread', None) and self._poll_thread.isRunning():
            return
        
        # 创建异步轮询线程
        class PollThread(QThread):
            result_ready = pyqtSignal(list)
            error = pyqtSignal(Exception)
            
            def __init__(self, auth_client, chat_type, recipient):
                super().__init__()
                self.auth_client = auth_client
                self.chat_type = chat_type
                self.recipient = recipient
            
            def run(self):
                try:
                    messages = self.auth_client.poll_chat_messages(self.chat_type, self.recipient)
                    self.result_ready.emit(messages)
                except Exception as exc:
                    self.error.emit(exc)
        
        session = self.chat_view.current_session()
        thread = PollThread(self._auth_client, session["chat_type"], session["recipient"])
        self._poll_thread = thread
        thread.result_ready.connect(self._on_poll_finished)
        thread.error.connect(self._on_poll_error)
        thread.finished.connect(lambda: self._clear_poll_thread(thread))
        thread.finished.connect(thread.deleteLater)
        thread.start()
    
    def _on_poll_finished(self, messages):
        """轮询完成处理"""
        self._display_chat_messages(messages, include_self=True)
        if messages:
            self.chat_view.heartbeat_status.set_value("刚刚", "okBadge")
            self.chat_view.security_status.set_value("群聊同步正常", "okBadge")
        self._refresh_online_users(throttle=True)

    def _clear_poll_thread(self, thread: QThread) -> None:
        """在线程真正退出后清理轮询线程引用。"""
        if self._poll_thread is thread:
            self._poll_thread = None

    @staticmethod
    def _is_ticket_expired_error(exc: Exception) -> bool:
        """判断是否为票据过期错误"""
        message = str(exc).lower()
        raw_message = str(exc)
        return (
            ("expired" in message and ("ticket" in message or "tgt" in message))
            or ("过期" in raw_message and ("票据" in raw_message or "TGT" in raw_message))
            or "session revoked" in message
            or "session_revoked" in message
            or "re-login" in message
            or "会话已被撤销" in raw_message
        )

    def _mark_reauth_required(self, reason: str) -> None:
        """标记需要重新认证
        
        参数:
            reason: 需要重新认证的原因
        """
        self.chat_view.security_status.set_value("票据已过期，请重新认证", "errorBadge")
        self.chat_view.heartbeat_status.set_value("已停止", "errorBadge")
        self.chat_view.relogin_button.setEnabled(True)
        self.chat_view.relogin_button.setObjectName("primaryButton")
        self.chat_view.relogin_button.style().unpolish(self.chat_view.relogin_button)
        self.chat_view.relogin_button.style().polish(self.chat_view.relogin_button)
        self.chat_view.add_message(f"安全提示：Kerberos 票据已失效，请点击“重新认证”。{reason}", "security")
    
    def _on_poll_error(self, exc):
        """轮询错误处理"""
        if self._is_ticket_expired_error(exc):
            self._mark_reauth_required(str(exc))
            self._poll_timer.stop()
            return
        self.chat_view.security_status.set_value("轮询失败", "errorBadge")
        self.chat_view.add_message(f"安全提示：拉取群聊消息失败，{exc}", "security")
        self._poll_timer.stop()

    def _refresh_online_users(self, throttle: bool = False) -> None:
        """后台刷新在线用户列表，避免网络请求阻塞 UI。"""
        if not self._auth_client:
            return

        now = time.monotonic()
        if throttle and now - self._last_user_refresh_at < 5:
            return
        if self._user_refresh_thread and self._user_refresh_thread.isRunning():
            return

        class UserListThread(QThread):
            result_ready = pyqtSignal(list)
            error = pyqtSignal(Exception)

            def __init__(self, auth_client: AuthClient) -> None:
                super().__init__()
                self.auth_client = auth_client

            def run(self) -> None:
                try:
                    self.result_ready.emit(self.auth_client.fetch_online_users())
                except Exception as exc:
                    self.error.emit(exc)

        thread = UserListThread(self._auth_client)
        self._user_refresh_thread = thread

        def on_finished(users: list[dict]) -> None:
            self._last_user_refresh_at = time.monotonic()
            self.chat_view.set_online_users(users)

        def on_error(exc: Exception) -> None:
            if self._is_ticket_expired_error(exc):
                self._mark_reauth_required(str(exc))
                self._poll_timer.stop()
                return
            message = str(exc)
            if "timed out" in message.lower() or "超时" in message:
                self.chat_view.security_status.set_value("用户列表刷新超时", "warnBadge")
                return
            now = time.monotonic()
            self.chat_view.security_status.set_value("用户列表异常", "errorBadge")
            if now - self._last_user_refresh_error_at > 30:
                self._last_user_refresh_error_at = now
                self.chat_view.add_message(f"安全提示：刷新在线用户失败，{exc}", "security")

        def cleanup() -> None:
            if self._user_refresh_thread is thread:
                self._user_refresh_thread = None

        thread.result_ready.connect(on_finished)
        thread.error.connect(on_error)
        thread.finished.connect(cleanup)
        thread.finished.connect(thread.deleteLater)
        thread.start()

    def _switch_chat_session(self) -> None:
        """切换聊天会话（群聊/私聊）"""
        self.chat_view.clear_messages()
        self._visible_message_ids.clear()
        session = self.chat_view.current_session()
        self.chat_view.session_type_status.set_value(session["title"], "okBadge")
        self.chat_view.add_message(f"系统通知：已切换到 {session['title']}", "system")
        
        if not self._auth_client:
            return
        
        # 重置会话游标并拉取消息
        self._auth_client.reset_session_cursor(session["chat_type"], session["recipient"])
        self._load_session_messages_async(session["chat_type"], session["recipient"], "会话")

    def _load_session_messages_async(self, chat_type: str, recipient: str, label: str) -> None:
        """后台加载当前会话消息，避免图片解密阻塞 UI。"""
        if not self._auth_client:
            return

        class SessionLoadThread(QThread):
            result_ready = pyqtSignal(str, str, list)
            error = pyqtSignal(str, str, Exception)

            def __init__(self, auth_client: AuthClient, chat_type: str, recipient: str) -> None:
                super().__init__()
                self.auth_client = auth_client
                self.chat_type = chat_type
                self.recipient = recipient

            def run(self) -> None:
                try:
                    messages = self.auth_client.poll_chat_messages(
                        self.chat_type,
                        self.recipient,
                        history_mode="latest",
                    )
                    self.result_ready.emit(self.chat_type, self.recipient, messages)
                except Exception as exc:
                    self.error.emit(self.chat_type, self.recipient, exc)

        self._session_load_generation += 1
        generation = self._session_load_generation
        thread = SessionLoadThread(self._auth_client, chat_type, recipient)

        def on_finished(done_type: str, done_recipient: str, messages: list) -> None:
            if generation != self._session_load_generation:
                return
            current = self.chat_view.current_session()
            if current["chat_type"] != done_type or current["recipient"] != done_recipient:
                return
            self._display_chat_messages(messages, include_self=True)

        def on_error(done_type: str, done_recipient: str, exc: Exception) -> None:
            if generation != self._session_load_generation:
                return
            current = self.chat_view.current_session()
            if current["chat_type"] != done_type or current["recipient"] != done_recipient:
                return
            if self._is_ticket_expired_error(exc):
                self._mark_reauth_required(str(exc))
                self._poll_timer.stop()
                return
            self.chat_view.security_status.set_value("轮询失败", "errorBadge")
            self.chat_view.add_message(f"安全提示：拉取{label}消息失败，{exc}", "security")

        def cleanup() -> None:
            if thread in self._session_load_threads:
                self._session_load_threads.remove(thread)

        thread.result_ready.connect(on_finished)
        thread.error.connect(on_error)
        thread.finished.connect(cleanup)
        thread.finished.connect(thread.deleteLater)
        self._session_load_threads.append(thread)
        thread.start()

    def _display_chat_messages(self, messages: list[dict], include_self: bool = False) -> None:
        """显示聊天消息
        
        参数:
            messages: 消息列表
            include_self: 是否包含自己发送的消息
        """
        if not self._auth_client:
            return
        
        from datetime import datetime
        
        self.chat_view.begin_message_batch()
        try:
            for message in messages:
                message_id = int(message.get("id", 0) or 0)
                session_key = self._view_session_key(
                    message.get("chat_type", "group"),
                    message.get("recipient", ""),
                )
                visible_key = (session_key, message_id)
                
                # 跳过已显示的消息
                if message_id and visible_key in self._visible_message_ids:
                    continue
                
                # 判断是否是自己发送的消息
                is_self = message["sender"] == self._auth_client.username
                if is_self and not include_self:
                    continue
                
                # 记录已显示的消息ID
                if message_id:
                    self._visible_message_ids.add(visible_key)
                
                # 准备消息参数
                kind = "self" if is_self else "peer"
                ciphertext = message.get("ciphertext", "")
                image_data = message.get("image_data", "")
                file_name = message.get("file_name", "")
                if not image_data and message_id in self._image_data_cache:
                    image_data, cached_name = self._image_data_cache[message_id]
                    self._image_data_cache.move_to_end(message_id)
                    file_name = file_name or cached_name
                has_image = bool(message.get("has_image") or image_data or file_name)
                username = message.get("sender") or self._auth_client.username
                
                # 时间戳转换（毫秒转可读格式）
                timestamp = message.get("timestamp", "")
                if timestamp:
                    try:
                        ts = int(timestamp) / 1000  # 毫秒转秒
                        timestamp = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
                    except:
                        timestamp = ""
                        
                # 添加消息到聊天视图，包含可选的 hmac/sig
                hmac_val = message.get("hmac", "")
                sig_val = message.get("sig", "")
                pubkey_val = message.get("pubkey", "")
                bubble = self.chat_view.add_message(message['text'], kind, ciphertext, image_data, file_name, username, timestamp, hmac_val, sig_val, pubkey_val)
                if has_image and not image_data and message_id:
                    self._fetch_message_image_async(message_id, bubble, file_name)
        finally:
            self.chat_view.end_message_batch()

    def _fetch_message_image_async(self, message_id: int, bubble, file_name: str) -> None:
        """后台拉取单条图片正文，避免阻塞会话消息列表。"""
        if not self._auth_client:
            return
        if message_id in self._image_data_cache or message_id in self._image_fetch_inflight:
            return

        class ImageFetchThread(QThread):
            result_ready = pyqtSignal(int, str, str)
            error = pyqtSignal(int, Exception)

            def __init__(self, auth_client: AuthClient, message_id: int) -> None:
                super().__init__()
                self.auth_client = auth_client
                self.message_id = message_id

            def run(self) -> None:
                try:
                    result = self.auth_client.fetch_message_image(self.message_id)
                    self.result_ready.emit(self.message_id, result["image_data"], result.get("file_name", ""))
                except Exception as exc:
                    self.error.emit(self.message_id, exc)

        self._image_fetch_inflight.add(message_id)
        thread = ImageFetchThread(self._auth_client, message_id)

        def on_finished(done_id: int, image_data: str, done_file_name: str) -> None:
            display_name = done_file_name or file_name
            self._remember_image_data(done_id, image_data, display_name)
            self.chat_view.set_message_image(bubble, image_data, display_name)

        def on_error(done_id: int, exc: Exception) -> None:
            pass

        def cleanup() -> None:
            if thread in self._image_fetch_threads:
                self._image_fetch_threads.remove(thread)
            self._image_fetch_inflight.discard(message_id)

        thread.result_ready.connect(on_finished)
        thread.error.connect(on_error)
        thread.finished.connect(cleanup)
        thread.finished.connect(thread.deleteLater)
        self._image_fetch_threads.append(thread)
        thread.start()

    def _remember_image_data(self, message_id: int, image_data: str, file_name: str) -> None:
        """缓存已解密图片正文，限制内存占用。"""
        self._image_data_cache[message_id] = (image_data, file_name)
        self._image_data_cache.move_to_end(message_id)
        while len(self._image_data_cache) > 60:
            self._image_data_cache.popitem(last=False)

    def closeEvent(self, event) -> None:
        """关闭窗口前停止后台线程，避免 QThread 析构时仍在运行。"""
        self._poll_timer.stop()
        self._stage_timer.stop()
        self._session_load_generation += 1
        self.chat_view.shutdown()

        threads: list[QThread] = []
        poll_thread = getattr(self, "_poll_thread", None)
        if poll_thread:
            threads.append(poll_thread)
        if self._user_refresh_thread:
            threads.append(self._user_refresh_thread)
        threads.extend(self._session_load_threads)
        threads.extend(self._image_fetch_threads)
        threads.extend(self._image_send_threads)

        seen: set[int] = set()
        active_threads: list[QThread] = []
        for thread in threads:
            thread_id = id(thread)
            if thread_id in seen:
                continue
            seen.add(thread_id)
            if thread.isRunning():
                active_threads.append(thread)
                thread.requestInterruption()

        for thread in active_threads:
            if not thread.wait(3000):
                thread.terminate()
                thread.wait(1000)

        super().closeEvent(event)

    def _view_session_key(self, chat_type: str = "group", recipient: str = "") -> str:
        """生成视图会话唯一标识"""
        if not self._auth_client:
            return "group:public"
        if chat_type == "private":
            users = sorted([self._auth_client.username, recipient])
            return f"private:{users[0]}:{users[1]}"
        return "group:public"

    def _open_private_chat(self, username: str) -> None:
        """打开与指定用户的私聊
        
        参数:
            username: 私聊对象用户名
        """
        if not self._auth_client:
            return
        
        # 不能与自己私聊
        if username == self._auth_client.username:
            QMessageBox.warning(self, "警告", "不能与自己发起私聊")
            return
        
        # 设置当前会话为私聊
        self.chat_view.set_current_session("private", username)
        
        # 清空消息并切换到私聊
        self.chat_view.clear_messages()
        self._visible_message_ids.clear()
        self.chat_view.session_type_status.set_value(f"私聊 {username}", "okBadge")
        self.chat_view.add_message(f"系统通知：已切换到私聊 {username}", "system")
        
        if not self._auth_client:
            return
        
        # 重置游标并拉取私聊消息
        self._auth_client.reset_session_cursor("private", username)
        self._load_session_messages_async("private", username, "私聊")

    def _return_to_group_chat(self) -> None:
        """从私聊返回群聊"""
        # 设置当前会话为群聊
        self.chat_view.set_current_session("group", "")
        
        self.chat_view.clear_messages()
        self._visible_message_ids.clear()
        self.chat_view.session_type_status.set_value("群聊大厅", "okBadge")
        self.chat_view.add_message("系统通知：已切换到群聊大厅", "system")
        
        if not self._auth_client:
            return
        
        # 重置游标并拉取群聊消息
        self._auth_client.reset_session_cursor("group", "")
        self._load_session_messages_async("group", "", "群聊")

    def _handle_relogin(self) -> None:
        """处理重新认证（刷新Kerberos票据和会话密钥）"""
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
        """管理员禁言用户
        
        参数:
            username: 被禁言的用户名
        """
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
        """管理员解除用户禁言
        
        参数:
            username: 被解除禁言的用户名
        """
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
        """发送图片消息
        
        流程:
        1. 弹出文件选择对话框
        2. 创建异步线程发送图片
        3. 显示上传进度
        4. 处理发送结果
        """
        from PyQt5.QtWidgets import QFileDialog
        import os
        
        if not self._auth_client:
            self.chat_view.add_message("系统提示：尚未完成认证，不能发送图片", "security")
            return
        
        # 弹出文件选择对话框
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "选择图片", 
            "", 
            "图片文件 (*.png *.jpg *.jpeg *.gif *.bmp)"
        )
        
        if not file_path:
            return
        
        # 显示上传进度条
        self.chat_view.show_upload_progress()
        self.chat_view.set_upload_progress(10)
        
        # 创建异步发送线程（避免阻塞UI）
        class ImageSendThread(QThread):
            result_ready = pyqtSignal(dict)
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
                    self.result_ready.emit(result)
                except Exception as exc:
                    self.error.emit(exc)

        def on_preview_ready(file_name, image_base64):
            pass
        
        def on_send_finished(result):
            try:
                self.chat_view.set_upload_progress(80, "正在处理响应...")
                
                if result.get("success"):
                    current = self.chat_view.current_session()
                    message_id = int(result.get("message_id", 0) or 0)
                    visible_key = (self._view_session_key(session["chat_type"], session["recipient"]), message_id)
                    
                    # 检查是否应该显示图片消息
                    if (
                        current["chat_type"] == session["chat_type"]
                        and current["recipient"] == session["recipient"]
                        and result.get("image_base64")
                        and (not message_id or visible_key not in self._visible_message_ids)
                    ):
                        from datetime import datetime
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        if message_id:
                            self._visible_message_ids.add(visible_key)
                        
                        # 添加图片消息到聊天视图
                        self.chat_view.add_message(
                            f"[图片] {result.get('file_name')}",
                            "self",
                            "",
                            result.get("image_base64", ""),
                            result.get("file_name", ""),
                            self._auth_client.username,
                            timestamp,
                        )
                    
                    self.chat_view.set_upload_progress(100, "上传完成！")
                    self.chat_view.add_message(f"图片发送成功：{result.get('file_name')}", "system")
                    self.chat_view.security_status.set_value("图片已发送", "okBadge")
                else:
                    self.chat_view.set_upload_progress(0, "上传失败")
                    self.chat_view.add_message(f"图片发送失败：{result.get('error', '未知错误')}", "security")
            finally:
                self.chat_view.hide_upload_progress()
                self.chat_view.image_button.setEnabled(True)
        
        def on_send_error(exc):
            try:
                self.chat_view.set_upload_progress(0, "发送失败")
                self.chat_view.add_message(f"安全提示：图片发送失败，{exc}", "security")
                self.chat_view.security_status.set_value("发送失败", "errorBadge")
            finally:
                self.chat_view.hide_upload_progress()
                self.chat_view.image_button.setEnabled(True)

        def cleanup_send_thread() -> None:
            if thread in self._image_send_threads:
                self._image_send_threads.remove(thread)
        
        # 启动发送线程
        self.chat_view.set_upload_progress(30, "正在初始化...")
        self.chat_view.image_button.setEnabled(False)
        session = self.chat_view.current_session()
        thread = ImageSendThread(
            self._auth_client,
            file_path,
            session["chat_type"],
            session["recipient"],
        )
        thread.result_ready.connect(on_send_finished)
        thread.error.connect(on_send_error)
        thread.progress.connect(self.chat_view.set_upload_progress)
        thread.preview_ready.connect(on_preview_ready)
        thread.finished.connect(cleanup_send_thread)
        thread.finished.connect(thread.deleteLater)
        self._image_send_threads.append(thread)
        thread.start()
