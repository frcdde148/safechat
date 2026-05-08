"""Core ticket-granting-server logic."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from typing import Any

from common.crypto.aes import encrypt_text
from common.crypto.des import encrypt_text as des_encrypt
from common.crypto.rsa_sign import generate_key_pair, sign_text
from common.models.tickets import decrypt_authenticator, decrypt_ticket, encrypt_model, issue_ticket
from common.protocol.security import body_digest
from database.dao.sqlite_dao import SQLiteDAO


@dataclass
class TGSResponse:
    """TGS server response structure."""
    success: bool
    client_id: str = ""
    encrypted_session_key: dict[str, str] = field(default_factory=dict)
    service_ticket: dict[str, str] = field(default_factory=dict)
    chat_host: str = ""
    chat_port: int = 0
    error: str = ""


class TicketGrantingServer:
    """
    Ticket Granting Server (TGS) - Kerberos V4 extended with digital signatures.
    
    Responsibilities:
    1. Verify Ticket Granting Ticket (TGT) validity
    2. Verify Authenticator for freshness check
    3. Generate session keys (Kc,v)
    4. Issue Service Tickets for ChatServer access
    5. Sign responses with RSA for non-repudiation
    6. Maintain audit logs with encrypted content
    """
    
    TGS_SERVICE = "tgs_server"
    CHAT_SERVICE = "chat_server"
    PROTOCOL_VERSION = "safechat-kerberos-v4-ext"
    TGS_SECRET_KEY = "tgs-server-secret-key-for-audit-encryption"
    
    def __init__(self, dao: SQLiteDAO | None = None) -> None:
        self.dao = dao or SQLiteDAO()
        self._private_key, self._public_key = generate_key_pair()
    
    def request_service_ticket(self, ticket_tgt: dict[str, str], authenticator: dict[str, str], 
                               client_addr: str, message_body: dict, message_hmac: str, 
                               message_sig: str, message_pubkey: str) -> TGSResponse:
        """
        Process C_TGS_REQ: validate TGT and authenticator, issue service ticket.
        
        Args:
            ticket_tgt: Encrypted TGT from client
            authenticator: Encrypted authenticator from client
            client_addr: Client IP address
            message_body: Original message body for verification
            message_hmac: HMAC digest from client
            message_sig: RSA signature from client
            message_pubkey: Client's public key
            
        Returns:
            TGSResponse containing service ticket and session key on success
        """
        # Get service configurations
        tgs_service = self.dao.get_service(self.TGS_SERVICE)
        chat_service = self.dao.get_service(self.CHAT_SERVICE)
        
        if not tgs_service:
            self._log_audit("", "unknown", client_addr, "TGS_ERROR", "TGS service not configured")
            return TGSResponse(success=False, error="TGS service not configured")
        
        if not chat_service:
            self._log_audit("", "unknown", client_addr, "TGS_ERROR", "Chat service not configured")
            return TGSResponse(success=False, error="Chat service not configured")
        
        try:
            # Decrypt TGT using TGS secret key
            tgt = decrypt_ticket(ticket_tgt, tgs_service["service_key"])
            
            # Validate TGT lifetime
            if not tgt.is_valid():
                self._log_audit("", tgt.client_id, client_addr, "TGS_ERROR", "TGT expired")
                return TGSResponse(success=False, error="TGT has expired")
            
            # Decrypt authenticator using session key from TGT
            auth = decrypt_authenticator(authenticator, tgt.session_key)
            
            # Validate authenticator client ID matches TGT
            if auth.client_id != tgt.client_id:
                self._log_audit("", tgt.client_id, client_addr, "TGS_ERROR", 
                               "Authenticator client ID mismatch")
                return TGSResponse(success=False, error="Authenticator client does not match TGT")
            
            # Validate client IP if present in authenticator
            if auth.client_addr and auth.client_addr != tgt.client_addr:
                self._log_audit("", tgt.client_id, client_addr, "TGS_ERROR", 
                               "Authenticator IP mismatch")
                return TGSResponse(success=False, error="Authenticator address does not match TGT")
            
            # Generate new session key for client-chatserver communication
            session_key_c_v = secrets.token_hex(16)
            
            # Issue service ticket encrypted with ChatServer's key
            service_ticket = issue_ticket(
                tgt.client_id,
                tgt.client_addr,
                session_key_c_v,
                self.CHAT_SERVICE,
            )
            encrypted_service_ticket = encrypt_model(service_ticket, chat_service["service_key"])
            
            # Encrypt session_key_c_v using Kc_tgs (session key from TGT)
            encrypted_session_key = des_encrypt(session_key_c_v, tgt.session_key)
            
            # Log successful ticket issuance
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
        Sign a response body with RSA.
        
        Returns:
            Tuple of (digest, signature)
        """
        digest = body_digest(response_body)
        signature = sign_text(digest, self._private_key)
        return digest, signature
    
    def get_public_key(self) -> str:
        """Return the TGS server's public key for verification."""
        return self._public_key
    
    def _log_audit(self, session_id: str, user_id: str, client_ip: str, 
                   action_type: str, content: str) -> None:
        """Log audit event with AES-encrypted content and RSA signature."""
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
