"""ChatServer entry point."""

from __future__ import annotations

import json
import threading
import time

from common.config.settings import server_bind_address
from common.crypto.des import decrypt_text, encrypt_text
from common.crypto.rsa_sign import generate_key_pair, sign_text
from common.models.tickets import decrypt_authenticator, decrypt_ticket, encrypt_model
from common.protocol.message import Message
from common.protocol.security import body_digest, verify_body_signature
from database.dao.sqlite_dao import SQLiteDAO
from server.simple_tcp_server import serve


CHAT_SERVICE = "chat_server"

# RSA key pair for signing responses
_private_key, _public_key = generate_key_pair()

dao = SQLiteDAO()
messages_lock = threading.Lock()
chat_messages: list[dict] = []
next_message_id = 1
online_lock = threading.Lock()
online_users: dict[str, dict] = {}  # username -> {session_id, client_ip, last_seen, status}
pubkey_lock = threading.Lock()
session_pubkeys: dict[str, str] = {}
ONLINE_TIMEOUT_MS = 30_000


def _sign_response(response_body: dict) -> tuple[str, str]:
    """Sign response body with RSA."""
    digest = body_digest(response_body)
    signature = sign_text(digest, _private_key)
    return digest, signature


def _get_public_key() -> str:
    """Return the ChatServer's public key."""
    return _public_key


def handle_message(message: dict, address: tuple[str, int]) -> Message:
    """Handle Client -> ChatServer auth and chat requests."""
    if message["type"] == "C_V_REQ":
        return _handle_mutual_auth(message, address)
    if message["type"] == "CHAT_SEND":
        return _handle_chat_send(message, address)
    if message["type"] == "IMAGE_SEND":
        return _handle_image_send(message, address)
    if message["type"] == "CHAT_POLL":
        return _handle_chat_poll(message, address)
    if message["type"] == "USER_LIST":
        return _handle_user_list(message, address)
    return Message(
        type="ERROR",
        seq=message["seq"],
        body={"error": "ChatServer only accepts C_V_REQ, CHAT_SEND, IMAGE_SEND, CHAT_POLL or USER_LIST"},
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

    # Verify session is valid (Single Sign-On check)
    session_id = message["body"].get("session_id", "")
    if not session_id:
        return Message(type="ERROR", seq=message["seq"], body={"error": "session_id is required"})

    active_session = dao.get_active_session(ticket.client_id)
    if not active_session or active_session["session_id"] != session_id:
        dao.add_audit_log(session_id, ticket.client_id, address[0], "CHAT_AUTH_FAILED_INVALID_SESSION")
        return Message(
            type="ERROR",
            seq=message["seq"],
            body={"error": "session is invalid or user logged in from another location"},
        )

    # Update session with service ticket info
    dao.update_session_service_ticket(session_id, ticket.issued_at, ticket.expires_at)

    mutual_auth = encrypt_model({"timestamp_plus_one": authenticator.timestamp + 1}, ticket.session_key)
    _mark_user_online(ticket.client_id, session_id, address[0])
    
    # Check for offline messages and push them
    offline_messages = dao.get_offline_messages(ticket.client_id)
    offline_messages_data = []
    for msg in offline_messages:
        # Encrypt message with recipient's session key
        message_cipher = encrypt_text(msg["message_text"], ticket.session_key)
        offline_messages_data.append({
            "id": msg["id"],
            "sender": msg["sender"],
            "message_cipher": message_cipher["ciphertext"],
            "iv": message_cipher["iv"],
            "chat_type": msg["chat_type"],
            "created_at": msg["created_at"],
        })
        # Delete the message from offline queue
        dao.delete_offline_message(msg["id"])
    
    dao.add_audit_log(session_id, ticket.client_id, address[0], "CHAT_AUTH_OK")
    
    response_body = {
        "client_id": ticket.client_id,
        "mutual_auth": mutual_auth,
        "offline_messages": offline_messages_data,
        "room": "public",
    }
    
    return Message(
        type="V_C_REP",
        seq=message["seq"],
        body=response_body,
    )


def _handle_chat_send(message: dict, address: tuple[str, int]) -> Message:
    """Decrypt one chat message and return an encrypted ACK."""
    ticket = _decrypt_valid_service_ticket(message)
    _update_user_last_seen(ticket.client_id)
    if not _verify_signed_message_for_ticket(message, ticket):
        dao.add_audit_log("", ticket.client_id, address[0], "CHAT_SIGN_FAILED")
        return Message(type="ERROR", seq=message["seq"], body={"error": "CHAT_SEND signature verification failed"})

    cipher = message["body"]["message_cipher"]
    plaintext = decrypt_text(cipher["ciphertext"], cipher["iv"], ticket.session_key)
    chat_type = message["body"].get("chat_type", "group")
    recipient = message["body"].get("recipient", "")
    print(f"[DEBUG] CHAT_SEND received: chat_type={chat_type}, recipient={recipient}, sender={ticket.client_id}")
    
    if chat_type == "private" and not recipient:
        return Message(type="ERROR", seq=message["seq"], body={"error": "private chat requires recipient"})
    
    # Check if recipient is online for private chat
    if chat_type == "private":
        with online_lock:
            is_recipient_online = recipient in online_users
            print(f"[DEBUG] Private chat check: chat_type={chat_type}, recipient={recipient}, online_users={list(online_users.keys())}, is_online={is_recipient_online}")
        
        if not is_recipient_online:
            # Recipient is offline, store plaintext message
            dao.store_offline_message(recipient, ticket.client_id, plaintext)
            ack_text = "已存储，待对方上线后推送"
            dao.add_audit_log(
                "",
                ticket.client_id,
                address[0],
                "CHAT_SEND_OFFLINE",
                content_enc=json.dumps({"recipient": recipient, "status": "stored"}, ensure_ascii=False),
            )
            return Message(
                type="CHAT_ACK",
                seq=message["seq"],
                body={
                    "sender": ticket.client_id,
                    "recipient": recipient,
                    "chat_type": chat_type,
                    "message_id": 0,
                    "ack_cipher": encrypt_text(ack_text, ticket.session_key),
                    "room": _session_key(ticket.client_id, chat_type, recipient),
                },
            )
    
    # Normal message processing for group chat or online private chat
    message_id = _append_chat_message(ticket.client_id, plaintext, chat_type, recipient)
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
            "recipient": recipient,
            "chat_type": chat_type,
            "message_id": message_id,
            "ack_cipher": encrypt_text(ack_text, ticket.session_key),
            "room": _session_key(ticket.client_id, chat_type, recipient),
        },
    )


def _handle_image_send(message: dict, address: tuple[str, int]) -> Message:
    """Handle image send request."""
    try:
        chat = dao.get_service(CHAT_SERVICE)
        if not chat:
            return Message(type="ERROR", seq=message["seq"], body={"error": "ChatServer service is not configured"})
        
        ticket = decrypt_ticket(message["body"]["service_ticket"], chat["service_key"])
        if not ticket.is_valid():
            return Message(type="ERROR", seq=message["seq"], body={"error": "service ticket is expired"})
        if not _verify_signed_message_for_ticket(message, ticket):
            return Message(type="ERROR", seq=message["seq"], body={"error": "invalid signature"})
        
        _update_user_last_seen(ticket.client_id)
        
        # Get image data from message
        image_cipher = message["body"]["image_cipher"]
        file_name = message["body"]["file_name"]
        file_size = message["body"]["file_size"]
        
        # Decrypt image data
        plaintext = decrypt_text(image_cipher["ciphertext"], image_cipher["iv"], ticket.session_key)
        
        # Store image in messages (as base64 string)
        chat_type = message["body"].get("chat_type", "group")
        recipient = message["body"].get("recipient", "")
        
        message_id = _append_chat_message(ticket.client_id, f"[图片] {file_name}", chat_type, recipient, plaintext, file_name)
        
        dao.add_audit_log(
            "",
            ticket.client_id,
            address[0],
            "IMAGE_SEND",
            content_enc=json.dumps({"file_name": file_name, "file_size": file_size}, ensure_ascii=False),
        )
        
        ack_text = f"图片 {file_name} 已接收，大小: {file_size} bytes"
        return Message(
            type="CHAT_ACK",
            seq=message["seq"],
            body={
                "sender": ticket.client_id,
                "recipient": recipient,
                "chat_type": chat_type,
                "message_id": message_id,
                "ack_cipher": encrypt_text(ack_text, ticket.session_key),
                "room": _session_key(ticket.client_id, chat_type, recipient),
            },
        )
    except Exception as e:
        print(f"[ERROR] _handle_image_send failed: {str(e)}")
        return Message(
            type="ERROR", 
            seq=message["seq"], 
            body={"error": f"image send failed: {str(e)}"}
        )


def _verify_signed_message_for_ticket(message: dict, ticket) -> bool:
    """Verify digest/RSA signature and bind the first post-login public key to the user."""
    if not message.get("hmac") or not message.get("sig") or not message.get("pubkey"):
        return False
    with pubkey_lock:
        existing_pubkey = session_pubkeys.get(ticket.client_id)
        if existing_pubkey and existing_pubkey != message["pubkey"]:
            return False
        session_pubkeys.setdefault(ticket.client_id, message["pubkey"])
    return verify_body_signature(
        message["body"],
        message["hmac"],
        message["sig"],
        message["pubkey"],
    )


def _handle_chat_poll(message: dict, address: tuple[str, int]) -> Message:
    """Return encrypted group-chat messages newer than last_seen_id."""
    ticket = _decrypt_valid_service_ticket(message)
    _update_user_last_seen(ticket.client_id)
    last_seen_id = int(message["body"].get("last_seen_id", 0))
    chat_type = message["body"].get("chat_type", "group")
    recipient = message["body"].get("recipient", "")
    session_key = _session_key(ticket.client_id, chat_type, recipient)
    
    with messages_lock:
        pending = [
            item.copy()
            for item in chat_messages
            if item["id"] > last_seen_id
            and item["session_key"] == session_key
            and _can_read_message(ticket.client_id, item)
        ]
    
    encrypted_messages = []
    for item in pending:
        msg_data = {
            "id": item["id"],
            "sender": item["sender"],
            "recipient": item["recipient"],
            "chat_type": item["chat_type"],
            "timestamp": item["timestamp"],
            "message_cipher": encrypt_text(item["text"], ticket.session_key),
        }
        # Include image data if present
        if item.get("image_data"):
            msg_data["image_data"] = item["image_data"]
            msg_data["file_name"] = item.get("file_name", "")
        encrypted_messages.append(msg_data)
    
    dao.add_audit_log("", ticket.client_id, address[0], "CHAT_POLL", content_enc=str(last_seen_id))
    return Message(
        type="CHAT_RECV",
        seq=message["seq"],
        body={
            "messages": encrypted_messages,
            "room": session_key,
        },
    )


def _handle_user_list(message: dict, address: tuple[str, int]) -> Message:
    """Return the current online user list."""
    ticket = _decrypt_valid_service_ticket(message)
    _update_user_last_seen(ticket.client_id)
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


def _append_chat_message(sender: str, text: str, chat_type: str, recipient: str, image_data: str = "", file_name: str = "") -> int:
    global next_message_id
    with messages_lock:
        message_id = next_message_id
        next_message_id += 1
        session_key = _session_key(sender, chat_type, recipient)
        chat_messages.append(
            {
                "id": message_id,
                "sender": sender,
                "recipient": recipient,
                "chat_type": chat_type,
                "session_key": session_key,
                "text": text,
                "image_data": image_data,
                "file_name": file_name,
                "timestamp": int(time.time() * 1000),
            }
        )
        return message_id


def _session_key(sender: str, chat_type: str, recipient: str) -> str:
    if chat_type == "private":
        users = sorted([sender, recipient])
        return f"private:{users[0]}:{users[1]}"
    return "group:public"


def _can_read_message(username: str, message: dict) -> bool:
    if message["chat_type"] == "private":
        return username in {message["sender"], message["recipient"]}
    return True


def _mark_user_online(username: str, session_id: str, client_ip: str) -> None:
    with online_lock:
        online_users[username] = {
            "username": username,
            "session_id": session_id,
            "client_ip": client_ip,
            "last_seen": int(time.time() * 1000),
            "status": "在线",
        }


def _update_user_last_seen(username: str) -> None:
    """Update user's last seen timestamp to keep them online."""
    with online_lock:
        if username in online_users:
            online_users[username]["last_seen"] = int(time.time() * 1000)


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
    host, port = server_bind_address("chat_server")
    serve(host, port, "ChatServer", handle_message)


if __name__ == "__main__":
    main()
