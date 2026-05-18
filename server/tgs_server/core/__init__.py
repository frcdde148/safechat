"""TGS票据授予服务器核心逻辑"""

from __future__ import annotations

import json
import secrets
import uuid
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
    client_part: dict[str, str] = field(default_factory=dict)
    extensions: dict[str, Any] = field(default_factory=dict)
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
                               message_sig: str) -> TGSResponse:
        """
        处理C_TGS_REQ请求: 验证TGT和Authenticator，签发服务票据
        
        参数:
            ticket_tgt: 客户端发送的加密TGT
            authenticator: 客户端发送的加密认证器
            client_addr: 客户端IP地址
            message_body: 原始消息体用于验证
            message_hmac: 客户端发送的HMAC摘要
            message_sig: 客户端的RSA签名
            
        返回:
            成功时返回包含服务票据和会话密钥的TGSResponse
        """
        # 获取服务配置
        print("魏心蕊")
        tgs_service = self.dao.get_service(self.TGS_SERVICE)
        chat_service = self.dao.get_service(self.CHAT_SERVICE)
        
        if not tgs_service:
            self._log_audit("", "unknown", client_addr, "TGS_ERROR", "TGS 服务未配置")
            return TGSResponse(success=False, error="TGS 服务未配置")
        
        if not chat_service:
            self._log_audit("", "unknown", client_addr, "TGS_ERROR", "ChatServer 服务未配置")
            return TGSResponse(success=False, error="ChatServer 服务未配置")
        
        try:
            # 使用TGS密钥解密TGT
            tgt = decrypt_ticket(ticket_tgt, tgs_service["service_key"])
            
            # 验证TGT有效期
            if not tgt.is_valid():
                debug = tgt.validity_debug()
                self._log_audit("", tgt.client_id, client_addr, "TGS_ERROR", f"TGT 已过期：{debug}")
                return TGSResponse(success=False, error=f"TGT 已过期：{debug}")
            
            # 使用TGT中的会话密钥解密Authenticator
            auth = decrypt_authenticator(authenticator, tgt.session_key)
            
            # 验证Authenticator客户端ID与TGT匹配
            if auth.client_id != tgt.client_id:
                self._log_audit("", tgt.client_id, client_addr, "TGS_ERROR", 
                               "认证器用户与 TGT 不匹配")
                return TGSResponse(success=False, error="认证器用户与 TGT 不匹配")
            
            # 如果Authenticator中包含IP，则验证客户端IP
            # 允许回环地址和本地地址匹配（适应开发环境）
            if auth.client_addr and tgt.client_addr:
                # 如果两个地址都是回环地址，则认为匹配
                auth_is_local = auth.client_addr.startswith("127.") or auth.client_addr == "::1"
                tgt_is_local = tgt.client_addr.startswith("127.") or tgt.client_addr == "::1"
                if auth_is_local and tgt_is_local:
                    pass  # 都是本地地址，跳过验证
                elif auth.client_addr != tgt.client_addr:
                    self._log_audit("", tgt.client_id, client_addr, "TGS_ERROR", 
                                   "认证器地址与 TGT 不匹配")
                    return TGSResponse(success=False, error="认证器地址与 TGT 不匹配")
            
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
            
            # 使用 Kc,tgs(TGT 中的会话密钥) 加密 session_key_c_v
            client_part = encrypt_text(
                json.dumps(
                    {
                        "k_c_v": session_key_c_v,
                        "id_v": self.CHAT_SERVICE,
                        "ad_c": tgt.client_addr,
                        "ts_4": service_ticket.issued_at,
                        "lifetime_4": service_ticket.expires_at,
                        "ticket_v": encrypted_service_ticket,
                        "chat_host": chat_service["service_host"],
                        "chat_port": chat_service["service_port"],
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
                tgt.session_key,
            )
            
            # 记录成功的票据签发
            self._log_audit("", tgt.client_id, client_addr, "TGS_TICKET_OK", 
                           f"Service ticket issued for {tgt.client_id}")
            
            return TGSResponse(
                success=True,
                client_part=client_part,
                extensions={
                    "version": self.PROTOCOL_VERSION,
                    "request_id": str(uuid.uuid4()),
                },
            )
            
        except Exception as e:
            self._log_audit("", "unknown", client_addr, "TGS_ERROR", f"解密或校验失败：{e}")
            return TGSResponse(success=False, error=f"票据校验失败：{e}")
    
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
