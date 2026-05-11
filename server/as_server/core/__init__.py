"""AS认证服务器核心逻辑"""

from __future__ import annotations

import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from common.crypto.des import encrypt_text
from common.crypto.rsa_sign import generate_key_pair, sign_text
from common.models.tickets import Ticket, encrypt_model, issue_ticket
from common.protocol.security import body_digest
from database.dao.sqlite_dao import SQLiteDAO


@dataclass
class ASResponse:
    """AS服务器响应数据结构"""
    success: bool
    client_id: str = ""
    encrypted_session_key: dict[str, str] = field(default_factory=dict)
    ticket_tgt: dict[str, str] = field(default_factory=dict)
    salt: str = ""
    tgs_host: str = ""
    tgs_port: int = 0
    error: str = ""
    version: str = "safechat-kerberos-v4-ext"
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str = ""


class AuthenticationServer:
    """
    认证服务器(AS) - 基于Kerberos V4扩展数字签名版本
    
    职责:
    1. 根据用户名查找用户的长期密钥
    2. 签发票据授予票据(TGT)
    3. 生成会话密钥(Kc,tgs)
    4. 使用RSA签名响应以实现不可否认性
    5. 维护加密的审计日志
    6. 检查IP封禁状态
    """
    
    TGS_SERVICE = "tgs_server"
    PROTOCOL_VERSION = "safechat-kerberos-v4-ext"
    AS_SECRET_KEY = "as-server-secret-key-for-audit-encryption"
    SESSION_ACTIVITY_TIMEOUT_MS = 45_000
    
    def __init__(self, dao: SQLiteDAO | None = None) -> None:
        self.dao = dao or SQLiteDAO(role="as")
        self._private_key, self._public_key = generate_key_pair()
    
    def authenticate(
        self,
        username: str,
        client_addr: str,
        message_body: dict,
        message_hmac: str = "",
        message_sig: str = "",
        message_pubkey: str = "",
    ) -> ASResponse:
        """
        用户认证并签发TGT票据
        
        参数:
            username: 用户用户名
            client_addr: 客户端IP地址
            message_body: 原始消息体用于验证
            message_hmac: 客户端发送的HMAC摘要
            message_sig: 客户端的RSA签名
            message_pubkey: 客户端的公钥
            
        返回:
            成功时返回包含TGT和加密会话密钥的ASResponse
        """
        if self.dao.is_ip_banned(client_addr):
            self._log_audit("", username or "unknown", client_addr, "LOGIN_FAILED", "IP banned")
            return ASResponse(success=False, error="client IP is banned")
        
        user = self.dao.get_user(username)
        if not user:
            self._log_audit("", username or "unknown", client_addr, "LOGIN_FAILED", "User not found")
            return ASResponse(success=False, error="invalid username or password")
        
        is_admin_console = message_body.get("client_type") == "admin_console" and user.get("role") == "admin"

        session_client_type = "admin_console" if is_admin_console else "client"
        existing_session = self.dao.get_active_session(username, session_client_type)
        if existing_session and not is_admin_console:
            now_ms = int(time.time() * 1000)
            existing_ip = existing_session["client_ip"]
            existing_ip_norm = self.dao._normalize_ip(existing_ip)
            client_ip_norm = self.dao._normalize_ip(client_addr)
            last_seen = int(existing_session.get("last_seen", 0) or 0)
            if existing_ip_norm != client_ip_norm and now_ms - last_seen <= self.SESSION_ACTIVITY_TIMEOUT_MS:
                self._log_audit(
                    "",
                    username,
                    client_addr,
                    "LOGIN_DENIED_DUPLICATE",
                    f"User {username} already logged in from {existing_ip}",
                )
                return ASResponse(
                    success=False,
                    error=f"user {username} is already logged in from {existing_ip}",
                )
            self.dao.invalidate_session(existing_session["session_id"])
        tgs_service = self.dao.get_service(self.TGS_SERVICE)
        if not tgs_service:
            return ASResponse(success=False, error="TGS service is not configured")
        
        session_key = secrets.token_hex(16)
        tgt = self._issue_tgt(username, client_addr, session_key)
        encrypted_tgt = encrypt_model(tgt, tgs_service["service_key"])
        
        client_key = user["password_hash"]
        encrypted_session_key = encrypt_text(session_key, client_key)
        
        session_id = secrets.token_hex(32)
        self.dao.create_session(
            username,
            session_id,
            client_addr,
            tgt.issued_at,
            tgt.expires_at,
            invalidate_existing=not is_admin_console,
            client_type=session_client_type,
        )
        
        self._log_audit(session_id, username, client_addr, "LOGIN_AS_OK", 
                        f"User {username} authenticated, TGT issued")
        
        return ASResponse(
            success=True,
            client_id=username,
            encrypted_session_key=encrypted_session_key,
            ticket_tgt=encrypted_tgt,
            salt=user["salt"],
            tgs_host=tgs_service["service_host"],
            tgs_port=tgs_service["service_port"],
            session_id=session_id,
        )
    
    def _issue_tgt(self, client_id: str, client_addr: str, session_key: str) -> Ticket:
        """签发票据授予票据(TGT)"""
        return issue_ticket(client_id, client_addr, session_key, self.TGS_SERVICE)
    
    def sign_response(self, response_body: dict[str, Any]) -> tuple[str, str]:
        """
        使用RSA签名响应体
        
        返回:
            (摘要, 签名) 元组
        """
        digest = body_digest(response_body)
        signature = sign_text(digest, self._private_key)
        return digest, signature
    
    def get_public_key(self) -> str:
        """返回AS服务器的公钥用于验证"""
        return self._public_key
    
    def _log_audit(self, session_id: str, user_id: str, client_ip: str, 
                   action_type: str, content: str) -> None:
        """记录审计事件，内容使用AES加密并使用RSA签名"""
        encrypted_content = encrypt_text(content, self.AS_SECRET_KEY)
        content_digest = body_digest({"content": content, "action_type": action_type})
        content_signature = sign_text(content_digest, self._private_key)
        self.dao.add_audit_log(
            session_id=session_id,
            user_id=user_id,
            client_ip=client_ip,
            action_type=action_type,
            content_enc=str(encrypted_content),
            signature=content_signature,
        )
