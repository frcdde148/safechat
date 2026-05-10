"""Client-side Kerberos authentication flow."""

from __future__ import annotations

import json
from typing import Any

from common.crypto.des import decrypt_text, encrypt_text
from common.crypto.rsa_sign import generate_key_pair
from common.crypto.sha256 import salted_password_hash
from common.models.tickets import encrypt_model, issue_authenticator
from common.protocol.message import Message
from common.protocol.security import sign_body
from common.protocol.socket_io import request


class AuthClient:
    """Run the six-step SafeChat/Kerberos authentication flow incrementally."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.username = payload["username"]
        self.password = payload["password"]
        self.client_type = payload.get("client_type", "client")
        self.as_host, self.as_port = payload["as"]
        self.tgs_host = ""
        self.tgs_port = 0
        self.chat_host = ""
        self.chat_port = 0
        self.seq = 1
        self.tgt: dict[str, str] | None = None
        self.service_ticket: dict[str, str] | None = None
        self.session_key_c_tgs = ""
        self.encrypted_session_key_c_tgs: dict[str, str] | None = None  # 保存加密的session_key
        self.session_key_c_v = ""
        self.encrypted_session_key_c_v: dict[str, str] | None = None  # 保存加密的session_key
        self.session_id = ""
        self.salt = ""
        self.client_key = ""
        self.last_message_ids: dict[str, int] = {}
        self.private_key_pem, self.public_key_pem = generate_key_pair()
        self.offline_messages: list[dict] = []

    def reset_session(self) -> None:
        """Reset session state for re-login."""
        self.seq = 1
        self.tgt = None
        self.service_ticket = None
        self.session_key_c_tgs = ""
        self.session_key_c_v = ""
        self.session_id = ""
        self.salt = ""
        self.client_key = ""
        self.last_message_ids = {}
        self.offline_messages = []

    def run_stage(self, stage_code: str) -> tuple[bool, str]:
        """Run one visible UI stage and return success plus display detail."""
        stage_handlers = {
            "C_AS_REQ": self._request_tgt,#映射。不用if else。
            "AS_C_REP": self._explain_as_response,
            "C_TGS_REQ": self._request_service_ticket,
            "TGS_C_REP": self._explain_tgs_response,
            "C_V_REQ": self._request_chat_auth,
            "V_C_REP": self._explain_chat_response,
        }
        try:
            return True, stage_handlers[stage_code]()
        except Exception as exc:
            return False, f"认证阶段失败：{exc}"

    def _request_tgt(self) -> str:
        body = {
            "username": self.username,
            "tgs_id": "tgs_server",
            "client_type": self.client_type,
        }
        message = Message(
            type="C_AS_REQ",
            seq=self._next_seq(),
            body=body,
        )
        response = request(self.as_host, self.as_port, message)
        self._raise_on_error(response)
        
        encrypted_session_key = response["body"].get("client_part", response["body"]["encrypted_session_key"])
        encrypted_tgt = response["body"]["ticket_tgt"]
        self.salt = response["body"]["salt"]
        self.client_key = salted_password_hash(self.password, self.salt)
        
        # 保存加密的 session_key
        self.encrypted_session_key_c_tgs = encrypted_session_key
        
        try:
            self.session_key_c_tgs = decrypt_text(
                encrypted_session_key["ciphertext"],
                encrypted_session_key["iv"],
                self.client_key,
            )
        except Exception as exc:
            raise ValueError("密码错误，无法用本地派生的长期密钥 Kc 解密 AS 响应") from exc
        self.tgt = encrypted_tgt
        self.tgs_host = response["body"]["tgs_host"]
        self.tgs_port = int(response["body"]["tgs_port"])
        self.session_id = response["body"].get("session_id", "")
        return self._format_exchange(message.to_dict(), response)

    def _explain_as_response(self) -> str:
        return self._format_state(
            {
                "client_saved": {
                    "encrypted_session_key": self.encrypted_session_key_c_tgs,
                    "salt": self.salt,
                    "ticket_tgt": self.tgt,
                    "tgs_server": f"{self.tgs_host}:{self.tgs_port}",
                }
            }
        )

    def _request_service_ticket(self) -> str:
        if not self.tgt:
            raise ValueError("missing TGT; run C_AS_REQ first")
        authenticator = encrypt_model(issue_authenticator(self.username, ""), self.session_key_c_tgs)
        body = {
            "service_id": "chat_server",
            "ticket_tgt": self.tgt,
            "authenticator": authenticator,
        }
        message = Message(
            type="C_TGS_REQ",
            seq=self._next_seq(),
            body=body,
        )
        response = request(self.tgs_host, self.tgs_port, message)
        self._raise_on_error(response)
        
        encrypted_session_key = response["body"]["encrypted_session_key"]
        
        # 保存加密的 session_key
        self.encrypted_session_key_c_v = encrypted_session_key
        
        self.session_key_c_v = decrypt_text(
            encrypted_session_key["ciphertext"],
            encrypted_session_key["iv"],
            self.session_key_c_tgs
        )
        self.service_ticket = response["body"]["service_ticket"]
        self.chat_host = response["body"].get("chat_host", self.chat_host)
        self.chat_port = response["body"].get("chat_port", self.chat_port)
        return self._format_exchange(message.to_dict(), response)

    def _explain_tgs_response(self) -> str:
        return self._format_state(
            {
                "client_saved": {
                    "encrypted_session_key": self.encrypted_session_key_c_v,
                    "service_ticket": self.service_ticket,
                    "chat_server": f"{self.chat_host}:{self.chat_port}",
                }
            }
        )

    def _request_chat_auth(self) -> str:
        if not self.service_ticket:
            raise ValueError("missing service ticket; run C_TGS_REQ first")
        authenticator = encrypt_model(issue_authenticator(self.username, ""), self.session_key_c_v)
        body = {
            "service_ticket": self.service_ticket,
            "authenticator": authenticator,
            "session_id": self.session_id,
        }
        message = Message(
            type="C_V_REQ",
            seq=self._next_seq(),
            body=body,
        )
        response = request(self.chat_host, self.chat_port, message)
        self._raise_on_error(response)
        
        # Save offline messages if any
        self.offline_messages = response["body"].get("offline_messages", [])
        
        return self._format_exchange(message.to_dict(), response)

    def _explain_chat_response(self) -> str:
        return self._format_state(
            {
                "authenticated": True,
                "room": "public",
                "message_security": "后续聊天消息使用 Kc,v 加密传输",
            }
        )

    def _next_seq(self) -> int:
        value = self.seq
        self.seq += 1
        return value

    def send_chat_message(self, text: str, chat_type: str = "group", recipient: str = "") -> dict[str, Any]:
        """Send one encrypted chat message using Kc,v and the service ticket."""
        if not self.service_ticket or not self.session_key_c_v:
            raise ValueError("chat session is not authenticated")
        message_cipher = encrypt_text(text, self.session_key_c_v)
        body = {
            "service_ticket": self.service_ticket,
            "message_cipher": message_cipher,
            "chat_type": chat_type,
            "recipient": recipient,
        }
        digest, signature = sign_body(body, self.private_key_pem)
        message = Message(
            type="CHAT_SEND",
            seq=self._next_seq(),
            body=body,
            hmac=digest,
            sig=signature,
            pubkey=self.public_key_pem,
        )
        response = request(self.chat_host, self.chat_port, message)
        self._raise_on_error(response)
        message_id = int(response["body"].get("message_id", 0))
        if message_id:
            session_key = self._session_key(chat_type, recipient)
            self.last_message_ids[session_key] = max(self.last_message_ids.get(session_key, 0), message_id)
        ack = response["body"].get("ack_cipher")
        plaintext_ack = ""
        if ack:
            plaintext_ack = decrypt_text(ack["ciphertext"], ack["iv"], self.session_key_c_v)
        return {
            "sent": message.to_dict(),
            "received": response,
            "ack": plaintext_ack,
            "message_id": message_id,
        }

    def send_image(
        self,
        file_path: str,
        progress_callback=None,
        chat_type: str = "group",
        recipient: str = "",
        preview_callback=None,
    ) -> dict[str, Any]:
        """Send an encrypted image to chat server."""
        import os
        from base64 import b64encode
        
        if not self.service_ticket or not self.session_key_c_v:
            raise ValueError("chat session is not authenticated")
        
        # Read and compress image file before encryption. Large raw photos are slow
        # after Base64 + JSON + DES, so keep chat images at a practical display size.
        if progress_callback:
            progress_callback(35, "正在压缩图片...")
        image_data, output_name, original_size = self._prepare_image_payload(file_path)
        
        # Limit image size to 10MB
        max_size = 10 * 1024 * 1024
        if len(image_data) > max_size:
            return {"success": False, "error": "压缩后图片仍超过限制（最大10MB）"}
        
        # Encode to base64 and encrypt
        if progress_callback:
            progress_callback(40, "正在编码图片...")
        image_base64 = b64encode(image_data).decode()
        if preview_callback:
            preview_callback(output_name, image_base64)
        
        if progress_callback:
            progress_callback(50, "正在加密数据...")
        image_cipher = encrypt_text(image_base64, self.session_key_c_v)
        
        if progress_callback:
            progress_callback(60, "正在准备发送...")
        
        body = {
            "service_ticket": self.service_ticket,
            "image_cipher": image_cipher,
            "file_name": output_name,
            "file_size": len(image_data),
            "original_size": original_size,
            "chat_type": chat_type,
            "recipient": recipient,
        }
        digest, signature = sign_body(body, self.private_key_pem)
        message = Message(
            type="IMAGE_SEND",
            seq=self._next_seq(),
            body=body,
            hmac=digest,
            sig=signature,
            pubkey=self.public_key_pem,
        )
        if progress_callback:
            progress_callback(70, "正在上传图片...")
        response = request(self.chat_host, self.chat_port, message, timeout=60.0)
        if progress_callback:
            progress_callback(75, "等待服务器响应...")
        self._raise_on_error(response)
        message_id = int(response["body"].get("message_id", 0))
        if message_id:
            session_key = self._session_key(chat_type, recipient)
            self.last_message_ids[session_key] = max(self.last_message_ids.get(session_key, 0), message_id)

        ack = response["body"].get("ack_cipher")
        plaintext_ack = ""
        if ack:
            plaintext_ack = decrypt_text(ack["ciphertext"], ack["iv"], self.session_key_c_v)

        return {
            "success": True,
            "file_name": output_name,
            "message_id": message_id,
            "ack": plaintext_ack,
        }

    @staticmethod
    def _prepare_image_payload(file_path: str) -> tuple[bytes, str, int]:
        """Return a compressed image payload, output filename, and original size."""
        import os
        from io import BytesIO

        with open(file_path, "rb") as file:
            original_data = file.read()

        try:
            from PIL import Image, ImageOps
        except ImportError:
            return original_data, os.path.basename(file_path), len(original_data)

        max_side = 1280
        try:
            with Image.open(file_path) as image:
                image = ImageOps.exif_transpose(image)
                image.thumbnail((max_side, max_side), Image.Resampling.LANCZOS)
                has_alpha = image.mode in ("RGBA", "LA") or (
                    image.mode == "P" and "transparency" in image.info
                )
                buffer = BytesIO()
                if has_alpha:
                    image.save(buffer, format="PNG", optimize=True)
                    extension = ".png"
                else:
                    if image.mode != "RGB":
                        image = image.convert("RGB")
                    image.save(buffer, format="JPEG", quality=75, optimize=True, progressive=True)
                    extension = ".jpg"
                compressed = buffer.getvalue()
        except Exception:
            return original_data, os.path.basename(file_path), len(original_data)

        base_name, _ = os.path.splitext(os.path.basename(file_path))
        return compressed, f"{base_name}_safechat{extension}", len(original_data)

    def poll_chat_messages(self, chat_type: str = "group", recipient: str = "") -> list[dict[str, Any]]:
        """Fetch and decrypt messages for one group/private session."""
        if not self.service_ticket or not self.session_key_c_v:
            raise ValueError("chat session is not authenticated")
        session_key = self._session_key(chat_type, recipient)
        message = Message(
            type="CHAT_POLL",
            seq=self._next_seq(),
            body={
                "service_ticket": self.service_ticket,
                "last_seen_id": self.last_message_ids.get(session_key, 0),
                "chat_type": chat_type,
                "recipient": recipient,
            },
        )
        response = request(self.chat_host, self.chat_port, message, timeout=30.0)
        self._raise_on_error(response)
        decrypted = []
        for item in response["body"].get("messages", []):
            cipher = item["message_cipher"]
            text = decrypt_text(cipher["ciphertext"], cipher["iv"], self.session_key_c_v)
            message_id = int(item["id"])
            self.last_message_ids[session_key] = max(self.last_message_ids.get(session_key, 0), message_id)
            msg_data = {
                "id": message_id,
                "sender": item["sender"],
                "recipient": item.get("recipient", ""),
                "chat_type": item.get("chat_type", "group"),
                "timestamp": item["timestamp"],
                "text": text,
                "ciphertext": str(cipher),
            }
            # Include image data if present
            if item.get("image_data"):
                msg_data["image_data"] = item["image_data"]
                msg_data["file_name"] = item.get("file_name", "")
            decrypted.append(msg_data)
        return decrypted

    def reset_session_cursor(self, chat_type: str = "group", recipient: str = "") -> None:
        """Reset one session cursor so switching views can reload recent messages."""
        self.last_message_ids[self._session_key(chat_type, recipient)] = 0

    def _session_key(self, chat_type: str = "group", recipient: str = "") -> str:
        if chat_type == "private":
            users = sorted([self.username, recipient])
            return f"private:{users[0]}:{users[1]}"
        return "group:public"

    def get_offline_messages(self) -> list[dict[str, Any]]:
        """Get and decrypt offline messages received during authentication."""
        decrypted = []
        for msg in self.offline_messages:
            text = decrypt_text(msg["message_cipher"], msg["iv"], self.session_key_c_v)
            decrypted.append({
                "id": msg["id"],
                "sender": msg["sender"],
                "recipient": self.username,
                "chat_type": msg["chat_type"],
                "timestamp": msg["created_at"],
                "text": text,
                "ciphertext": msg["message_cipher"],
            })
        # Clear offline messages after retrieving
        self.offline_messages = []
        return decrypted

    def fetch_online_users(self) -> list[dict[str, Any]]:
        """Fetch the current ChatServer online user list."""
        if not self.service_ticket or not self.session_key_c_v:
            raise ValueError("chat session is not authenticated")
        message = Message(
            type="USER_LIST",
            seq=self._next_seq(),
            body={
                "service_ticket": self.service_ticket,
            },
        )
        response = request(self.chat_host, self.chat_port, message)
        self._raise_on_error(response)
        return response["body"].get("users", [])

    def admin_mute_user(self, target_username: str, duration_seconds: int = 600, reason: str = "admin mute") -> dict[str, Any]:
        """Ask ChatServer to mute one user. Server enforces admin permission."""
        return self._send_admin_action(
            "ADMIN_MUTE_USER",
            {
                "target_username": target_username,
                "duration_seconds": duration_seconds,
                "reason": reason,
            },
        )

    def admin_unmute_user(self, target_username: str) -> dict[str, Any]:
        """Ask ChatServer to revoke active mute rules for one user."""
        return self._send_admin_action(
            "ADMIN_UNMUTE_USER",
            {
                "target_username": target_username,
            },
        )

    def admin_kick_user(self, target_username: str) -> dict[str, Any]:
        """Ask ChatServer to remove one user from the online table."""
        return self._send_admin_action(
            "ADMIN_KICK_USER",
            {
                "target_username": target_username,
            },
        )

    def request_admin_token(self) -> str:
        """Request an AS-signed admin token using the existing TGT, not the password."""
        if not self.tgt or not self.session_key_c_tgs:
            raise ValueError("missing TGT; complete Kerberos authentication first")
        authenticator = encrypt_model(issue_authenticator(self.username, ""), self.session_key_c_tgs)
        message = Message(
            type="AS_ADMIN_TOKEN_REQ",
            seq=self._next_seq(),
            body={
                "ticket_tgt": self.tgt,
                "authenticator": authenticator,
            },
        )
        response = request(self.as_host, self.as_port, message, timeout=10.0)
        self._raise_on_error(response)
        token = response["body"].get("admin_token", "")
        if not token:
            raise RuntimeError("AS did not return admin token")
        return token

    def chat_admin_list_messages(self, chat_type: str = "All", user_filter: str = "", limit: int = 200) -> list[dict[str, Any]]:
        """Query chat messages through ChatServer admin API."""
        body = self._send_admin_action(
            "CHAT_ADMIN_LIST_MESSAGES",
            {
                "chat_type": chat_type,
                "user_filter": user_filter,
                "limit": limit,
            },
        )
        return body.get("messages", [])

    def chat_admin_audit_query(self, action_filter: str = "", limit: int = 300) -> list[dict[str, Any]]:
        """Query ChatServer audit logs through ChatServer admin API."""
        body = self._send_admin_action(
            "CHAT_ADMIN_AUDIT_QUERY",
            {
                "action_filter": action_filter,
                "limit": limit,
            },
        )
        return body.get("audit_logs", [])

    def chat_admin_set_role(self, target_username: str, role: str) -> dict[str, Any]:
        """Set ChatServer-local user role through ChatServer admin API."""
        return self._send_admin_action(
            "CHAT_ADMIN_SET_ROLE",
            {
                "target_username": target_username,
                "role": role,
            },
        )

    def chat_admin_delete_user(self, target_username: str) -> dict[str, Any]:
        """Delete ChatServer-local user copy through ChatServer admin API."""
        return self._send_admin_action(
            "CHAT_ADMIN_DELETE_USER",
            {
                "target_username": target_username,
            },
        )

    def _send_admin_action(self, action_type: str, body_fields: dict[str, Any]) -> dict[str, Any]:
        if not self.service_ticket or not self.session_key_c_v:
            raise ValueError("chat session is not authenticated")
        body = {
            "service_ticket": self.service_ticket,
            **body_fields,
        }
        digest, signature = sign_body(body, self.private_key_pem)
        message = Message(
            type=action_type,
            seq=self._next_seq(),
            body=body,
            hmac=digest,
            sig=signature,
            pubkey=self.public_key_pem,
        )
        response = request(self.chat_host, self.chat_port, message)
        self._raise_on_error(response)
        return response["body"]

    @staticmethod
    def _raise_on_error(response: dict[str, Any]) -> None:
        if response["type"] == "ERROR":
            raise RuntimeError(response["body"].get("error", "unknown server error"))

    @staticmethod
    def _format_exchange(sent: dict[str, Any], received: dict[str, Any]) -> str:
        return json.dumps({"send": sent, "receive": received}, ensure_ascii=False, indent=2)

    @staticmethod
    def _format_state(state: dict[str, Any]) -> str:
        return json.dumps(state, ensure_ascii=False, indent=2)
