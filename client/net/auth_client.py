"""Client-side Kerberos authentication flow."""

from __future__ import annotations

import json
from typing import Any

from common.crypto.des import decrypt_text, encrypt_text
from common.crypto.rsa_sign import generate_key_pair
from common.models.tickets import encrypt_model, issue_authenticator
from common.protocol.message import Message
from common.protocol.security import sign_body
from common.protocol.socket_io import request


class AuthClient:
    """Run the six-step SafeChat/Kerberos authentication flow incrementally."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.username = payload["username"]
        self.password = payload["password"]
        self.as_host, self.as_port = payload["as"]
        self.tgs_host, self.tgs_port = payload["tgs"]
        self.chat_host, self.chat_port = payload["chat"]
        self.seq = 1
        self.tgt: dict[str, str] | None = None
        self.service_ticket: dict[str, str] | None = None
        self.session_key_c_tgs = ""
        self.session_key_c_v = ""
        self.last_message_id = 0
        self.private_key_pem, self.public_key_pem = generate_key_pair()

    def run_stage(self, stage_code: str) -> tuple[bool, str]:
        """Run one visible UI stage and return success plus display detail."""
        stage_handlers = {
            "C_AS_REQ": self._request_tgt,
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
        message = Message(
            type="C_AS_REQ",
            seq=self._next_seq(),
            body={
                "username": self.username,
                "password": self.password,
                "tgs_id": "tgs_server",
            },
        )
        response = request(self.as_host, self.as_port, message)
        self._raise_on_error(response)
        self.session_key_c_tgs = response["body"]["session_key_c_tgs"]
        self.tgt = response["body"]["ticket_tgt"]
        return self._format_exchange(message.to_dict(), response)

    def _explain_as_response(self) -> str:
        return self._format_state(
            {
                "client_saved": {
                    "session_key_c_tgs": self.session_key_c_tgs,
                    "ticket_tgt": self.tgt,
                }
            }
        )

    def _request_service_ticket(self) -> str:
        if not self.tgt:
            raise ValueError("missing TGT; run C_AS_REQ first")
        authenticator = encrypt_model(issue_authenticator(self.username, ""), self.session_key_c_tgs)
        message = Message(
            type="C_TGS_REQ",
            seq=self._next_seq(),
            body={
                "service_id": "chat_server",
                "ticket_tgt": self.tgt,
                "authenticator": authenticator,
            },
        )
        response = request(self.tgs_host, self.tgs_port, message)
        self._raise_on_error(response)
        self.session_key_c_v = response["body"]["session_key_c_v"]
        self.service_ticket = response["body"]["service_ticket"]
        self.chat_host = response["body"].get("chat_host", self.chat_host)
        self.chat_port = response["body"].get("chat_port", self.chat_port)
        return self._format_exchange(message.to_dict(), response)

    def _explain_tgs_response(self) -> str:
        return self._format_state(
            {
                "client_saved": {
                    "session_key_c_v": self.session_key_c_v,
                    "service_ticket": self.service_ticket,
                    "chat_server": f"{self.chat_host}:{self.chat_port}",
                }
            }
        )

    def _request_chat_auth(self) -> str:
        if not self.service_ticket:
            raise ValueError("missing service ticket; run C_TGS_REQ first")
        authenticator = encrypt_model(issue_authenticator(self.username, ""), self.session_key_c_v)
        message = Message(
            type="C_V_REQ",
            seq=self._next_seq(),
            body={
                "service_ticket": self.service_ticket,
                "authenticator": authenticator,
            },
        )
        response = request(self.chat_host, self.chat_port, message)
        self._raise_on_error(response)
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

    def send_chat_message(self, text: str) -> dict[str, Any]:
        """Send one encrypted chat message using Kc,v and the service ticket."""
        if not self.service_ticket or not self.session_key_c_v:
            raise ValueError("chat session is not authenticated")
        message_cipher = encrypt_text(text, self.session_key_c_v)
        body = {
            "service_ticket": self.service_ticket,
            "message_cipher": message_cipher,
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
        ack = response["body"].get("ack_cipher")
        plaintext_ack = ""
        if ack:
            plaintext_ack = decrypt_text(ack["ciphertext"], ack["iv"], self.session_key_c_v)
        return {
            "sent": message.to_dict(),
            "received": response,
            "ack": plaintext_ack,
        }

    def poll_chat_messages(self) -> list[dict[str, Any]]:
        """Fetch and decrypt group-chat messages newer than last_message_id."""
        if not self.service_ticket or not self.session_key_c_v:
            raise ValueError("chat session is not authenticated")
        message = Message(
            type="CHAT_POLL",
            seq=self._next_seq(),
            body={
                "service_ticket": self.service_ticket,
                "last_seen_id": self.last_message_id,
            },
        )
        response = request(self.chat_host, self.chat_port, message)
        self._raise_on_error(response)
        decrypted = []
        for item in response["body"].get("messages", []):
            cipher = item["message_cipher"]
            text = decrypt_text(cipher["ciphertext"], cipher["iv"], self.session_key_c_v)
            message_id = int(item["id"])
            self.last_message_id = max(self.last_message_id, message_id)
            decrypted.append(
                {
                    "id": message_id,
                    "sender": item["sender"],
                    "timestamp": item["timestamp"],
                    "text": text,
                }
            )
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
