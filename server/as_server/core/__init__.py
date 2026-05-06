"""Core authentication-server logic."""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass, field
from typing import Any

from common.crypto.aes import encrypt_text
from common.crypto.rsa_sign import generate_key_pair, sign_text
from common.models.tickets import Ticket, encrypt_model, issue_ticket
from common.protocol.security import body_digest
from database.dao.sqlite_dao import SQLiteDAO


@dataclass
class ASResponse:
    """AS server response structure."""
    success: bool
    client_id: str = ""
    session_key_c_tgs: str = ""
    ticket_tgt: dict[str, str] = field(default_factory=dict)
    tgs_host: str = ""
    tgs_port: int = 0
    error: str = ""
    version: str = "safechat-kerberos-v4-ext"
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))


class AuthenticationServer:
    """
    Authentication Server (AS) - Kerberos V4 extended with digital signatures.
    
    Responsibilities:
    1. Verify user credentials (username/password)
    2. Issue Ticket Granting Tickets (TGT)
    3. Generate session keys (Kc,tgs)
    4. Sign responses with RSA for non-repudiation
    5. Maintain audit logs with encrypted content
    6. Check IP ban status
    """
    
    TGS_SERVICE = "tgs_server"
    PROTOCOL_VERSION = "safechat-kerberos-v4-ext"
    AS_SECRET_KEY = "as-server-secret-key-for-audit-encryption"
    
    def __init__(self, dao: SQLiteDAO | None = None) -> None:
        self.dao = dao or SQLiteDAO()
        self._private_key, self._public_key = generate_key_pair()
    
    def authenticate(self, username: str, password: str, client_addr: str) -> ASResponse:
        """
        Authenticate user and issue TGT.
        
        Args:
            username: User's username
            password: User's password
            client_addr: Client IP address
            
        Returns:
            ASResponse containing TGT and session key on success
        """
        # Check IP ban status
        if self.dao.is_ip_banned(client_addr):
            self._log_audit("", username or "unknown", client_addr, "LOGIN_FAILED", "IP banned")
            return ASResponse(success=False, error="client IP is banned")
        
        # Verify credentials
        if not self.dao.verify_user_password(username, password):
            self._log_audit("", username or "unknown", client_addr, "LOGIN_FAILED", "Invalid credentials")
            return ASResponse(success=False, error="invalid username or password")
        
        # Get TGS service configuration
        tgs_service = self.dao.get_service(self.TGS_SERVICE)
        if not tgs_service:
            return ASResponse(success=False, error="TGS service is not configured")
        
        # Generate session key and TGT
        session_key = secrets.token_hex(16)
        tgt = self._issue_tgt(username, client_addr, session_key)
        encrypted_tgt = encrypt_model(tgt, tgs_service["service_key"])
        
        # Log successful authentication
        self._log_audit("", username, client_addr, "LOGIN_AS_OK", 
                        f"User {username} authenticated, TGT issued")
        
        return ASResponse(
            success=True,
            client_id=username,
            session_key_c_tgs=session_key,
            ticket_tgt=encrypted_tgt,
            tgs_host=tgs_service["service_host"],
            tgs_port=tgs_service["service_port"],
        )
    
    def _issue_tgt(self, client_id: str, client_addr: str, session_key: str) -> Ticket:
        """Issue a Ticket Granting Ticket (TGT)."""
        return issue_ticket(client_id, client_addr, session_key, self.TGS_SERVICE)
    
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
        """Return the AS server's public key for verification."""
        return self._public_key
    
    def _log_audit(self, session_id: str, user_id: str, client_ip: str, 
                   action_type: str, content: str) -> None:
        """Log audit event with AES-encrypted content and RSA signature."""
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