"""ChatServer entry point."""

from __future__ import annotations

import json
import threading
import time

from common.config.settings import server_bind_address
from common.crypto.des import decrypt_text, encrypt_text
from common.models.tickets import decrypt_authenticator, decrypt_ticket, encrypt_model
from common.protocol.message import Message
from common.protocol.security import verify_body_signature
from database.dao.sqlite_dao import SQLiteDAO
from server.simple_tcp_server import serve


CHAT_SERVICE = "chat_server"

dao = SQLiteDAO(role="chat")
online_lock = threading.Lock()
online_users: dict[str, dict] = {}  # username -> {session_id, client_ip, last_seen, status}
pubkey_lock = threading.Lock()
session_pubkeys: dict[str, str] = {}
ONLINE_TIMEOUT_MS = 30_000


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
    if message["type"] == "ADMIN_MUTE_USER":
        return _handle_admin_mute_user(message, address)
    if message["type"] == "ADMIN_UNMUTE_USER":
        return _handle_admin_unmute_user(message, address)
    if message["type"] == "ADMIN_KICK_USER":
        return _handle_admin_kick_user(message, address)
    if message["type"] == "CHAT_ADMIN_LIST_MESSAGES":
        return _handle_chat_admin_list_messages(message, address)
    if message["type"] == "CHAT_ADMIN_AUDIT_QUERY":
        return _handle_chat_admin_audit_query(message, address)
    if message["type"] == "CHAT_ADMIN_SET_ROLE":
        return _handle_chat_admin_set_role(message, address)
    return Message(
        type="ERROR",
        seq=message["seq"],
        body={"error": "ChatServer only accepts C_V_REQ, CHAT_SEND, IMAGE_SEND, CHAT_POLL, USER_LIST or ADMIN_*"},
    )


def _handle_mutual_auth(message: dict, address: tuple[str, int]) -> Message:
    """Handle Kerberos mutual authentication."""
    chat = dao.get_service(CHAT_SERVICE)
    if not chat:
        return Message(type="ERROR", seq=message["seq"], body={"error": "ChatServer service is not configured"})

    ticket = decrypt_ticket(message["body"]["service_ticket"], chat["service_key"])
    if not ticket.is_valid():
        return Message(
            type="ERROR",
            seq=message["seq"],
            body={"error": f"service ticket is expired: {ticket.validity_debug()}"},
        )
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
    session_id = message["body"].get("session_id", "")
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
    mute_error = _mute_error(ticket.client_id)
    if mute_error:
        dao.add_audit_log("", ticket.client_id, address[0], "CHAT_SEND_MUTED", content_enc=mute_error)
        return Message(type="ERROR", seq=message["seq"], body={"error": mute_error})

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
            return Message(
                type="ERROR",
                seq=message["seq"],
                body={"error": f"service ticket is expired: {ticket.validity_debug()}"},
            )
        if not _verify_signed_message_for_ticket(message, ticket):
            return Message(type="ERROR", seq=message["seq"], body={"error": "invalid signature"})
        
        _update_user_last_seen(ticket.client_id)
        mute_error = _mute_error(ticket.client_id)
        if mute_error:
            dao.add_audit_log("", ticket.client_id, address[0], "IMAGE_SEND_MUTED", content_enc=mute_error)
            return Message(type="ERROR", seq=message["seq"], body={"error": mute_error})
        
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


def _verify_admin_request(message: dict, ticket) -> bool:
    """Verify request signature and require the sender to have admin role."""
    if not _verify_signed_message_for_ticket(message, ticket):
        return False
    user = dao.get_user(ticket.client_id)
    return bool(user and user.get("role") == "admin")


def _mute_error(username: str) -> str:
    """Return an error string when a user is currently muted."""
    rule = dao.get_active_mute("user", username)
    if not rule:
        return ""
    return (
        f"user {username} is muted until {rule['expires_at']}; "
        f"reason: {rule.get('reason', '')}"
    )


def _handle_chat_poll(message: dict, address: tuple[str, int]) -> Message:
    """Return encrypted group-chat messages newer than last_seen_id."""
    ticket = _decrypt_valid_service_ticket(message)
    _update_user_last_seen(ticket.client_id)
    last_seen_id = int(message["body"].get("last_seen_id", 0))
    chat_type = message["body"].get("chat_type", "group")
    recipient = message["body"].get("recipient", "")
    session_key = _session_key(ticket.client_id, chat_type, recipient)
    
    pending = dao.list_chat_messages(session_key, last_seen_id, ticket.client_id)
    
    encrypted_messages = []
    for item in pending:
        msg_data = {
            "id": item["id"],
            "sender": item["sender"],
            "recipient": item["recipient"],
            "chat_type": item["chat_type"],
            "timestamp": item.get("created_at", item.get("timestamp", 0)),
            "message_cipher": encrypt_text(item.get("message_text", item.get("text", "")), ticket.session_key),
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
    """Return the full contact list with online/offline state."""
    ticket = _decrypt_valid_service_ticket(message)
    _update_user_last_seen(ticket.client_id)
    users = _current_contact_users()
    dao.add_audit_log("", ticket.client_id, address[0], "USER_LIST", content_enc=str(len(users)))
    return Message(
        type="USER_LIST",
        seq=message["seq"],
        body={
            "users": users,
            "count": len(users),
        },
    )


def _handle_admin_mute_user(message: dict, address: tuple[str, int]) -> Message:
    """Mute one user after verifying the operator is an administrator."""
    ticket = _decrypt_valid_service_ticket(message)
    _update_user_last_seen(ticket.client_id)
    if not _verify_admin_request(message, ticket):
        dao.add_audit_log("", ticket.client_id, address[0], "ADMIN_MUTE_DENIED")
        return Message(type="ERROR", seq=message["seq"], body={"error": "admin permission required"})

    target = message["body"].get("target_username", "").strip()
    duration_seconds = int(message["body"].get("duration_seconds", 600))
    reason = message["body"].get("reason", "admin mute")
    if not target:
        return Message(type="ERROR", seq=message["seq"], body={"error": "target_username is required"})
    if target == ticket.client_id:
        return Message(type="ERROR", seq=message["seq"], body={"error": "administrator cannot mute self"})
    if not dao.get_user(target):
        return Message(type="ERROR", seq=message["seq"], body={"error": f"user not found: {target}"})

    duration_seconds = max(60, min(duration_seconds, 24 * 60 * 60))
    expires_at = int(time.time() * 1000) + duration_seconds * 1000
    rule_id = dao.add_mute_rule(
        target_type="user",
        target_value=target,
        muted_by=ticket.client_id,
        expires_at=expires_at,
        reason=reason,
    )
    payload = {"target": target, "expires_at": expires_at, "reason": reason, "rule_id": rule_id}
    dao.add_audit_log(
        "",
        ticket.client_id,
        address[0],
        "ADMIN_MUTE_USER",
        content_enc=json.dumps(payload, ensure_ascii=False),
    )
    return Message(
        type="ADMIN_MUTE_ACK",
        seq=message["seq"],
        body={
            "target_username": target,
            "expires_at": expires_at,
            "rule_id": rule_id,
            "ack": f"{target} muted until {expires_at}",
        },
    )


def _handle_admin_unmute_user(message: dict, address: tuple[str, int]) -> Message:
    """Revoke active user mute rules after administrator verification."""
    ticket = _decrypt_valid_service_ticket(message)
    _update_user_last_seen(ticket.client_id)
    if not _verify_admin_request(message, ticket):
        dao.add_audit_log("", ticket.client_id, address[0], "ADMIN_UNMUTE_DENIED")
        return Message(type="ERROR", seq=message["seq"], body={"error": "admin permission required"})

    target = message["body"].get("target_username", "").strip()
    if not target:
        return Message(type="ERROR", seq=message["seq"], body={"error": "target_username is required"})
    affected = dao.revoke_mute_rule("user", target)
    payload = {"target": target, "affected": affected}
    dao.add_audit_log(
        "",
        ticket.client_id,
        address[0],
        "ADMIN_UNMUTE_USER",
        content_enc=json.dumps(payload, ensure_ascii=False),
    )
    return Message(
        type="ADMIN_UNMUTE_ACK",
        seq=message["seq"],
        body={
            "target_username": target,
            "affected": affected,
            "ack": f"{target} unmuted",
        },
    )


def _handle_admin_kick_user(message: dict, address: tuple[str, int]) -> Message:
    """Remove one user from ChatServer's in-memory online table."""
    ticket = _decrypt_valid_service_ticket(message)
    _update_user_last_seen(ticket.client_id)
    if not _verify_admin_request(message, ticket):
        dao.add_audit_log("", ticket.client_id, address[0], "ADMIN_KICK_DENIED")
        return Message(type="ERROR", seq=message["seq"], body={"error": "admin permission required"})

    target = message["body"].get("target_username", "").strip()
    if not target:
        return Message(type="ERROR", seq=message["seq"], body={"error": "target_username is required"})
    if target == ticket.client_id:
        return Message(type="ERROR", seq=message["seq"], body={"error": "administrator cannot kick self"})

    with online_lock:
        existed = target in online_users
        online_users.pop(target, None)
    dao.add_audit_log(
        "",
        ticket.client_id,
        address[0],
        "ADMIN_KICK_USER",
        content_enc=json.dumps({"target": target, "was_online": existed}, ensure_ascii=False),
    )
    return Message(
        type="ADMIN_KICK_ACK",
        seq=message["seq"],
        body={
            "target_username": target,
            "was_online": existed,
            "ack": f"{target} kicked",
        },
    )


def _handle_chat_admin_list_messages(message: dict, address: tuple[str, int]) -> Message:
    """Return chat messages for admin review."""
    ticket = _decrypt_valid_service_ticket(message)
    _update_user_last_seen(ticket.client_id)
    if not _verify_admin_request(message, ticket):
        return Message(type="ERROR", seq=message["seq"], body={"error": "admin permission required"})
    body = message["body"]
    chat_type = body.get("chat_type", "All")
    user_filter = body.get("user_filter", "")
    params: list = []
    query = """
        SELECT id, created_at, chat_type, session_key, sender, recipient, message_text, file_name
        FROM chat_messages
    """
    clauses = []
    if chat_type != "All":
        clauses.append("chat_type = ?")
        params.append(chat_type)
    if user_filter:
        clauses.append("(sender LIKE ? OR recipient LIKE ?)")
        params.extend([f"%{user_filter}%", f"%{user_filter}%"])
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(int(body.get("limit", 200)))
    with dao._connect() as conn:
        rows = conn.execute(query, params).fetchall()
        messages = [dict(row) for row in rows]
    dao.add_audit_log("", ticket.client_id, address[0], "CHAT_ADMIN_LIST_MESSAGES", content_enc=str(len(messages)))
    return Message(type="CHAT_ADMIN_ACK", seq=message["seq"], body={"messages": messages})


def _handle_chat_admin_audit_query(message: dict, address: tuple[str, int]) -> Message:
    """Return ChatServer audit logs for admin review."""
    ticket = _decrypt_valid_service_ticket(message)
    _update_user_last_seen(ticket.client_id)
    if not _verify_admin_request(message, ticket):
        return Message(type="ERROR", seq=message["seq"], body={"error": "admin permission required"})
    body = message["body"]
    action_filter = body.get("action_filter", "")
    params: list = []
    query = "SELECT id, timestamp, user_id, client_ip, action_type, content_enc, signature FROM audit_logs"
    if action_filter:
        query += " WHERE action_type LIKE ?"
        params.append(f"%{action_filter}%")
    query += " ORDER BY id DESC LIMIT ?"
    params.append(int(body.get("limit", 300)))
    with dao._connect() as conn:
        rows = conn.execute(query, params).fetchall()
        logs = [dict(row) for row in rows]
    return Message(type="CHAT_ADMIN_ACK", seq=message["seq"], body={"audit_logs": logs})


def _handle_chat_admin_set_role(message: dict, address: tuple[str, int]) -> Message:
    """Update ChatServer-local user role."""
    ticket = _decrypt_valid_service_ticket(message)
    _update_user_last_seen(ticket.client_id)
    if not _verify_admin_request(message, ticket):
        return Message(type="ERROR", seq=message["seq"], body={"error": "admin permission required"})
    target = message["body"].get("target_username", "")
    role = message["body"].get("role", "user")
    if role not in {"user", "admin"}:
        return Message(type="ERROR", seq=message["seq"], body={"error": "invalid role"})
    with dao._connect() as conn:
        conn.execute("UPDATE users SET role = ? WHERE username = ?", (role, target))
        conn.commit()
    dao.add_audit_log("", ticket.client_id, address[0], "CHAT_ADMIN_SET_ROLE", content_enc=json.dumps({"target": target, "role": role}, ensure_ascii=False))
    return Message(type="CHAT_ADMIN_ACK", seq=message["seq"], body={"updated": target, "role": role})


def _decrypt_valid_service_ticket(message: dict):
    chat = dao.get_service(CHAT_SERVICE)
    if not chat:
        raise ValueError("ChatServer service is not configured")
    ticket = decrypt_ticket(message["body"]["service_ticket"], chat["service_key"])
    if not ticket.is_valid():
        raise ValueError(f"service ticket is expired: {ticket.validity_debug()}")
    return ticket


def _append_chat_message(sender: str, text: str, chat_type: str, recipient: str, image_data: str = "", file_name: str = "") -> int:
    session_key = _session_key(sender, chat_type, recipient)
    return dao.store_chat_message(
        sender=sender,
        recipient=recipient,
        chat_type=chat_type,
        session_key=session_key,
        message_text=text,
        image_data=image_data,
        file_name=file_name,
    )


def _session_key(sender: str, chat_type: str, recipient: str) -> str:
    if chat_type == "private":
        users = sorted([sender, recipient])
        return f"private:{users[0]}:{users[1]}"
    return "group:public"


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


def _current_contact_users() -> list[dict]:
    """Merge the persisted user directory with current ChatServer online state."""
    online = {item["username"]: item for item in _current_online_users()}
    contacts = []
    for user in dao.list_users():
        username = user["username"]
        if username in online:
            contact = dict(online[username])
        else:
            contact = {
                "username": username,
                "session_id": "",
                "client_ip": "",
                "last_seen": 0,
                "status": "离线",
            }
        contact["role"] = user.get("role", "user")
        mute_rule = dao.get_active_mute("user", username)
        contact["muted"] = bool(mute_rule)
        contact["muted_until"] = mute_rule["expires_at"] if mute_rule else 0
        contacts.append(contact)
    for username, item in online.items():
        if not any(contact["username"] == username for contact in contacts):
            contacts.append(item)
    return sorted(contacts, key=lambda item: item["username"])


def main() -> None:
    """Start the chat server."""
    host, port = server_bind_address("chat_server")
    serve(host, port, "ChatServer", handle_message)


if __name__ == "__main__":
    main()
