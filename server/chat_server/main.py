"""ChatServer entry point."""

from __future__ import annotations

import json
import threading
import time

from common.crypto.des import decrypt_text, encrypt_text
from common.models.tickets import decrypt_authenticator, decrypt_ticket, encrypt_model
from common.protocol.message import Message
from common.protocol.security import verify_body_signature
from database.dao.sqlite_dao import SQLiteDAO
from server.simple_tcp_server import serve


HOST = "127.0.0.1"
PORT = 9000
CHAT_SERVICE = "chat_server"


dao = SQLiteDAO()
messages_lock = threading.Lock()
chat_messages: list[dict] = []
next_message_id = 1
online_lock = threading.Lock()
online_users: dict[str, dict] = {}
ONLINE_TIMEOUT_MS = 30_000


def handle_message(message: dict, address: tuple[str, int]) -> Message:
    """Handle Client -> ChatServer auth and chat requests."""
    if message["type"] == "C_V_REQ":
        return _handle_mutual_auth(message, address)
    if message["type"] == "CHAT_SEND":
        return _handle_chat_send(message, address)
    if message["type"] == "CHAT_POLL":
        return _handle_chat_poll(message, address)
    if message["type"] == "USER_LIST":
        return _handle_user_list(message, address)
    return Message(
        type="ERROR",
        seq=message["seq"],
        body={"error": "ChatServer only accepts C_V_REQ, CHAT_SEND, CHAT_POLL or USER_LIST"},
    )


def _handle_mutual_auth(message: dict, address: tuple[str, int]) -> Message:
    """Handle Kerberos mutual authentication."""
    chat = dao.get_service(CHAT_SERVICE)
    if not chat:
        return Message(type="ERROR", seq=message["seq"], body={"error": "ChatServer service is not configured"})

    ticket = decrypt_ticket(message["body"]["service_ticket"], chat["service_key"])
    if not ticket.is_valid():
        return Message(type="ERROR", seq=message["seq"], body={"error": "service ticket is expired"})
    authenticator = decrypt_authenticator(message["body"]["authenticator"], ticket.session_key)
    if authenticator.client_id != ticket.client_id:
        return Message(
            type="ERROR",
            seq=message["seq"],
            body={"error": "authenticator client does not match service ticket"},
        )
    if authenticator.client_addr and authenticator.client_addr != ticket.client_addr:
        return Message(type="ERROR", seq=message["seq"], body={"error": "authenticator does not match service ticket"})

    mutual_auth = encrypt_model({"timestamp_plus_one": authenticator.timestamp + 1}, ticket.session_key)
    _mark_user_online(ticket.client_id, address[0])
    dao.add_audit_log("", ticket.client_id, address[0], "CHAT_AUTH_OK")
    return Message(
        type="V_C_REP",
        seq=message["seq"],
        body={
            "client_id": ticket.client_id,
            "mutual_auth": mutual_auth,
            "room": "public",
        },
    )


def _handle_chat_send(message: dict, address: tuple[str, int]) -> Message:
    """Decrypt one chat message and return an encrypted ACK."""
    ticket = _decrypt_valid_service_ticket(message)
    if not _verify_signed_chat_message(message):
        dao.add_audit_log("", ticket.client_id, address[0], "CHAT_SIGN_FAILED")
        return Message(type="ERROR", seq=message["seq"], body={"error": "CHAT_SEND signature verification failed"})

    cipher = message["body"]["message_cipher"]
    plaintext = decrypt_text(cipher["ciphertext"], cipher["iv"], ticket.session_key)
    message_id = _append_chat_message(ticket.client_id, plaintext)
    dao.add_audit_log(
        "",
        ticket.client_id,
        address[0],
        "CHAT_SEND",
        content_enc=json.dumps(cipher, ensure_ascii=False),
    )
    ack_text = f"ChatServer 已收到 {ticket.client_id} 的加密消息：{plaintext}"
    return Message(
        type="CHAT_ACK",
        seq=message["seq"],
        body={
            "sender": ticket.client_id,
            "message_id": message_id,
            "ack_cipher": encrypt_text(ack_text, ticket.session_key),
            "room": "public",
        },
    )


def _verify_signed_chat_message(message: dict) -> bool:
    """Verify CHAT_SEND digest and RSA signature fields."""
    if not message.get("hmac") or not message.get("sig") or not message.get("pubkey"):
        return False
    return verify_body_signature(
        message["body"],
        message["hmac"],
        message["sig"],
        message["pubkey"],
    )


def _handle_chat_poll(message: dict, address: tuple[str, int]) -> Message:
    """Return encrypted group-chat messages newer than last_seen_id."""
    ticket = _decrypt_valid_service_ticket(message)
    _mark_user_online(ticket.client_id, address[0])
    last_seen_id = int(message["body"].get("last_seen_id", 0))
    with messages_lock:
        pending = [item.copy() for item in chat_messages if item["id"] > last_seen_id]
    encrypted_messages = []
    for item in pending:
        encrypted_messages.append(
            {
                "id": item["id"],
                "sender": item["sender"],
                "timestamp": item["timestamp"],
                "message_cipher": encrypt_text(item["text"], ticket.session_key),
            }
        )
    dao.add_audit_log("", ticket.client_id, address[0], "CHAT_POLL", content_enc=str(last_seen_id))
    return Message(
        type="CHAT_RECV",
        seq=message["seq"],
        body={
            "messages": encrypted_messages,
            "room": "public",
        },
    )


def _handle_user_list(message: dict, address: tuple[str, int]) -> Message:
    """Return the current online user list."""
    ticket = _decrypt_valid_service_ticket(message)
    _mark_user_online(ticket.client_id, address[0])
    users = _current_online_users()
    dao.add_audit_log("", ticket.client_id, address[0], "USER_LIST", content_enc=str(len(users)))
    return Message(
        type="USER_LIST",
        seq=message["seq"],
        body={
            "users": users,
            "count": len(users),
        },
    )


def _decrypt_valid_service_ticket(message: dict):
    chat = dao.get_service(CHAT_SERVICE)
    if not chat:
        raise ValueError("ChatServer service is not configured")
    ticket = decrypt_ticket(message["body"]["service_ticket"], chat["service_key"])
    if not ticket.is_valid():
        raise ValueError("service ticket is expired")
    return ticket


def _append_chat_message(sender: str, text: str) -> int:
    global next_message_id
    with messages_lock:
        message_id = next_message_id
        next_message_id += 1
        chat_messages.append(
            {
                "id": message_id,
                "sender": sender,
                "text": text,
                "timestamp": int(time.time() * 1000),
            }
        )
        return message_id


def _mark_user_online(username: str, client_ip: str) -> None:
    with online_lock:
        online_users[username] = {
            "username": username,
            "client_ip": client_ip,
            "last_seen": int(time.time() * 1000),
            "status": "在线",
        }


def _current_online_users() -> list[dict]:
    now_ms = int(time.time() * 1000)
    with online_lock:
        expired = [
            username
            for username, item in online_users.items()
            if now_ms - int(item["last_seen"]) > ONLINE_TIMEOUT_MS
        ]
        for username in expired:
            del online_users[username]
        return sorted(online_users.values(), key=lambda item: item["username"])


def main() -> None:
    """Start the chat server."""
    serve(HOST, PORT, "ChatServer", handle_message)


if __name__ == "__main__":
    main()
