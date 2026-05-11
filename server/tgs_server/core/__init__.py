"""TGS票据授予服务器核心逻辑"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from typing import Any

from common.crypto.des import encrypt_text
from common.crypto.rsa_sign import generate_key_pair, sign_text
from common.models.tickets import decrypt_authenticator, decrypt_ticket, encrypt_model, issue_ticket
from common.protocol.security import body_digest
from database.dao.sqlite_dao import SQLiteDAO


@dataclass
class TGSResponse:
    """TGS服务器响应数据结构"""
    success: bool
    client_id: str = ""
    encrypted_session_key: dict[str, str] = field(default_factory=dict)
    service_ticket: dict[str, str] = field(default_factory=dict)
    chat_host: str = ""
    chat_port: int = 0
    error: str = ""


class TicketGrantingServer:
    """
    票据授予服务器(TGS) - 基于Kerberos V4扩展数字签名版本
    
    职责:
    1. 验证票据授予票据(TGT)的有效性
    2. 验证Authenticator以检查新鲜性
    3. 生成会话密钥(Kc,v)
    4. 签发ChatServer访问的服务票据
    5. 使用RSA签名响应以实现不可否认性
    6. 维护加密的审计日志
    """
    
    TGS_SERVICE = "tgs_server"
    CHAT_SERVICE = "chat_server"
    PROTOCOL_VERSION = "safechat-kerberos-v4-ext"
    TGS_SECRET_KEY = "tgs-server-secret-key-for-audit-encryption"
    
    def __init__(self, dao: SQLiteDAO | None = None) -> None:
        self.dao = dao or SQLiteDAO(role="tgs")
        self._private_key, self._public_key = generate_key_pair()
    
    def request_service_ticket(self, ticket_tgt: dict[str, str], authenticator: dict[str, str], 
                               client_addr: str, message_body: dict, message_hmac: str, 
                               message_sig: str, message_pubkey: str) -> TGSResponse:
        """
        处理C_TGS_REQ请求: 验证TGT和Authenticator，签发服务票据
        
        参数:
            ticket_tgt: 客户端发送的加密TGT
            authenticator: 客户端发送的加密认证器
            client_addr: 客户端IP地址
            message_body: 原始消息体用于验证
            message_hmac: 客户端发送的HMAC摘要
            message_sig: 客户端的RSA签名
            message_pubkey: 客户端的公钥
            
        返回:
            成功时返回包含服务票据和会话密钥的TGSResponse
        """
        # 获取服务配置
        tgs_service = self.dao.get_service(self.TGS_SERVICE)
        chat_service = self.dao.get_service(self.CHAT_SERVICE)
        
        if not tgs_service:
            self._log_audit("", "unknown", client_addr, "TGS_ERROR", "TGS service not configured")
            return TGSResponse(success=False, error="TGS service not configured")
        
        if not chat_service:
            self._log_audit("", "unknown", client_addr, "TGS_ERROR", "Chat service not configured")
            return TGSResponse(success=False, error="Chat service not configured")
        
        try:
            # 使用TGS密钥解密TGT
            tgt = decrypt_ticket(ticket_tgt, tgs_service["service_key"])
            
            # 验证TGT有效期
            if not tgt.is_valid():
                debug = tgt.validity_debug()
                self._log_audit("", tgt.client_id, client_addr, "TGS_ERROR", f"TGT expired: {debug}")
                return TGSResponse(success=False, error=f"TGT has expired: {debug}")
            
            # 使用TGT中的会话密钥解密Authenticator
            auth = decrypt_authenticator(authenticator, tgt.session_key)
            
            # 验证Authenticator客户端ID与TGT匹配
            if auth.client_id != tgt.client_id:
                self._log_audit("", tgt.client_id, client_addr, "TGS_ERROR", 
                               "Authenticator client ID mismatch")
                return TGSResponse(success=False, error="Authenticator client does not match TGT")
            
            # 如果Authenticator中包含IP，则验证客户端IP
            if auth.client_addr and auth.client_addr != tgt.client_addr:
                self._log_audit("", tgt.client_id, client_addr, "TGS_ERROR", 
                               "Authenticator IP mismatch")
                return TGSResponse(success=False, error="Authenticator address does not match TGT")
            
            # 生成客户端与ChatServer通信的新会话密钥
            session_key_c_v = secrets.token_hex(16)
            
            # 签发使用ChatServer密钥加密的服务票据
            service_ticket = issue_ticket(
                tgt.client_id,
                tgt.client_addr,
                session_key_c_v,
                self.CHAT_SERVICE,
            )
            encrypted_service_ticket = encrypt_model(service_ticket, chat_service["service_key"])
            
            # 使用Kc,tgs(TGT中的会话密钥)加密session_key_c_v
            encrypted_session_key = encrypt_text(session_key_c_v, tgt.session_key)
            
            # 记录成功的票据签发
            self._log_audit("", tgt.client_id, client_addr, "TGS_TICKET_OK", 
                           f"Service ticket issued for {tgt.client_id}")
            
            return TGSResponse(
                success=True,
                client_id=tgt.client_id,
                encrypted_session_key=encrypted_session_key,
                service_ticket=encrypted_service_ticket,
                chat_host=chat_service["service_host"],
                chat_port=chat_service["service_port"],
            )
            
        except Exception as e:
            self._log_audit("", "unknown", client_addr, "TGS_ERROR", f"Decryption/validation failed: {str(e)}")
            return TGSResponse(success=False, error=f"Ticket validation failed: {str(e)}")
    
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
        """返回TGS服务器的公钥用于验证"""
        return self._public_key
    
    def _log_audit(self, session_id: str, user_id: str, client_ip: str, 
                   action_type: str, content: str) -> None:
        """记录审计事件，内容使用AES加密并使用RSA签名"""
        encrypted_content = encrypt_text(content, self.TGS_SECRET_KEY)
        content_digest = body_digest({"content": content, "action_type": action_type})
        content_signature = sign_text(content_digest, self._private_key)
        self.dao.add_audit_log(
            session_id=session_id,
            user_id=user_id,
            client_ip=client_ip,
            action_type=action_type,
            content_enc=json.dumps(encrypted_content),
            signature=content_signature,
        )
