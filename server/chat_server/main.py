"""ChatServer聊天服务器入口文件"""

from __future__ import annotations

import json
import threading
import time

from common.config.settings import server_bind_address, service_address
from common.crypto.des import decrypt_text, encrypt_text
from common.models.tickets import decrypt_authenticator, decrypt_ticket, encrypt_model
from common.protocol.message import Message
from common.protocol.security import verify_body_signature
from database.dao.sqlite_dao import SQLiteDAO
from database.init_db import ensure_database
from server.simple_tcp_server import serve


CHAT_SERVICE = "chat_server"  # 聊天服务标识

dao = SQLiteDAO(role="chat")  # 数据库访问对象
online_lock = threading.Lock()  # 在线用户列表线程锁（多用户同时在线安全）
online_users: dict[str, dict] = {}  # 在线用户列表 {用户名: {session_id, client_ip, last_seen, status}}
pubkey_lock = threading.Lock()  # 公钥绑定线程锁
session_pubkeys: dict[str, str] = {}  # 用户公钥绑定
ONLINE_TIMEOUT_MS = 30_000  # 30秒无心跳 → 离线


def handle_message(message: dict, address: tuple[str, int]) -> Message:
    """处理客户端到ChatServer的认证和聊天请求"""
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
    if message["type"] == "CHAT_ADMIN_DELETE_USER":
        return _handle_chat_admin_delete_user(message, address)
    return Message(
        type="ERROR",
        seq=message["seq"],
        body={"error": "ChatServer only accepts C_V_REQ, CHAT_SEND, IMAGE_SEND, CHAT_POLL, USER_LIST or ADMIN_*"},
    )


def _handle_mutual_auth(message: dict, address: tuple[str, int]) -> Message:
    """处理Kerberos双向认证（Kerberos第六步）"""
    chat = dao.get_service(CHAT_SERVICE)
    if not chat:
        return Message(type="ERROR", seq=message["seq"], body={"error": "ChatServer service is not configured"})

    body = message.get("body", {})
    extensions = body.get("extensions", {}) if isinstance(body.get("extensions", {}), dict) else {}
    ticket = decrypt_ticket(body.get("ticket_v", body.get("service_ticket", {})), chat["service_key"])
    if not ticket.is_valid():
        return Message(
            type="ERROR",
            seq=message["seq"],
            body={"error": f"service ticket is expired: {ticket.validity_debug()}"},
        )
    authenticator = decrypt_authenticator(body.get("authenticator_c", body.get("authenticator", {})), ticket.session_key)
    if authenticator.client_id != ticket.client_id:
        return Message(
            type="ERROR",
            seq=message["seq"],
            body={"error": "authenticator client does not match service ticket"},
        )
    if authenticator.client_addr and authenticator.client_addr != ticket.client_addr:
        return Message(type="ERROR", seq=message["seq"], body={"error": "authenticator does not match service ticket"})

    mutual_auth = encrypt_model({"ts_5_plus_1": authenticator.timestamp + 1}, ticket.session_key)
    session_id = str(extensions.get("session_id", body.get("session_id", "")))
    _mark_user_online(ticket.client_id, session_id, address[0])
    public_key_pem = str(extensions.get("public_key_pem", body.get("public_key_pem", "") or message.get("pubkey", "")) or "")
    if not public_key_pem:
        return Message(type="ERROR", seq=message["seq"], body={"error": "client public key is required"})
    with pubkey_lock:
        session_pubkeys[_pubkey_scope(ticket.client_id, ticket.session_key)] = public_key_pem
    dao.clear_session_revocations(ticket.client_id)
    
    # 检查离线消息并推送
    offline_messages = dao.get_offline_messages(ticket.client_id)
    offline_messages_data = []
    for msg in offline_messages:
        # 用接收者的会话密钥加密消息
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
        "client_part": mutual_auth,
        "extensions": {
            "offline_messages": offline_messages_data,
            "room": "public",
        },
    }
    
    return Message(
        type="V_C_REP",
        seq=message["seq"],
        body=response_body,
    )


def _handle_chat_send(message: dict, address: tuple[str, int]) -> Message:
    """解密聊天消息并返回加密的确认响应"""
    ticket = _decrypt_valid_service_ticket(message)
    revoked = _revoked_session_error(message, ticket, address)
    if revoked:
        return revoked
    _update_user_last_seen(ticket.client_id, address[0])
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
            # Keep offline private messages in durable chat history so the
            # sender and recipient both see them after switching sessions.
            message_id = _append_chat_message(
                ticket.client_id,
                plaintext,
                chat_type,
                recipient,
                image_data="",
                file_name="",
            )
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
                    "message_id": message_id,
                    "ack_cipher": encrypt_text(ack_text, ticket.session_key),
                    "room": _session_key(ticket.client_id, chat_type, recipient),
                },
            )
    
    # Normal message processing for group chat or online private chat
    # Persist original sender HMAC/SIG for later display
    message_id = dao.store_chat_message(
        sender=ticket.client_id,
        recipient=recipient,
        chat_type=chat_type,
        session_key=_session_key(ticket.client_id, chat_type, recipient),
        message_text=plaintext,
        message_hmac=message.get("hmac", ""),
        message_sig=message.get("sig", ""),
        message_pubkey=_session_pubkey(ticket.client_id, ticket.session_key),
        image_data="",
        file_name="",
    )
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
    """处理图片发送请求"""
    try:
        chat = dao.get_service(CHAT_SERVICE)
        if not chat:
            return Message(type="ERROR", seq=message["seq"], body={"error": "ChatServer service is not configured"})
        
        body = message.get("body", {})
        ticket = decrypt_ticket(body.get("ticket_v", body.get("service_ticket", {})), chat["service_key"])
        if not ticket.is_valid():
            return Message(
                type="ERROR",
                seq=message["seq"],
                body={"error": f"service ticket is expired: {ticket.validity_debug()}"},
            )
        revoked = _revoked_session_error(message, ticket, address)
        if revoked:
            return revoked
        if not _verify_signed_message_for_ticket(message, ticket):
            return Message(type="ERROR", seq=message["seq"], body={"error": "invalid signature"})
        
        _update_user_last_seen(ticket.client_id, address[0])
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
        
        # Persist image message along with sender HMAC/SIG
        message_id = dao.store_chat_message(
            sender=ticket.client_id,
            recipient=recipient,
            chat_type=chat_type,
            session_key=_session_key(ticket.client_id, chat_type, recipient),
            message_text=plaintext,
            message_hmac=message.get("hmac", ""),
            message_sig=message.get("sig", ""),
            message_pubkey=_session_pubkey(ticket.client_id, ticket.session_key),
            image_data=file_name,
            file_name=file_name,
        )
        
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
    """验证消息的摘要/RSA签名，并将首次登录后的公钥绑定到用户"""
    if not message.get("hmac") or not message.get("sig"):
        return False
    with pubkey_lock:
        bound_pubkey = session_pubkeys.get(_pubkey_scope(ticket.client_id, ticket.session_key), "")
    if not bound_pubkey:
        return False
    return verify_body_signature(
        message["body"],
        message["hmac"],
        message["sig"],
        bound_pubkey,
    )


def _pubkey_scope(username: str, session_key: str) -> str:
    return f"{username}:{session_key}"


def _session_pubkey(username: str, session_key: str) -> str:
    with pubkey_lock:
        return session_pubkeys.get(_pubkey_scope(username, session_key), "")


def _verify_admin_request(message: dict, ticket) -> bool:
    """验证请求签名并要求发送者具有管理员角色"""
    if not _verify_signed_message_for_ticket(message, ticket):
        return False
    user = dao.get_user(ticket.client_id)
    return bool(user and user.get("role") == "admin")


def _mute_error(username: str) -> str:
    """当用户被禁言时返回错误字符串"""
    rule = dao.get_active_mute("user", username)
    if not rule:
        return ""
    return (
        f"user {username} is muted until {rule['expires_at']}; "
        f"reason: {rule.get('reason', '')}"
    )


def _handle_chat_poll(message: dict, address: tuple[str, int]) -> Message:
    """返回比last_seen_id更新的加密群聊消息"""
    ticket = _decrypt_valid_service_ticket(message)
    revoked = _revoked_session_error(message, ticket, address)
    if revoked:
        return revoked
    _update_user_last_seen(ticket.client_id, address[0])
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
            "hmac": item.get("message_hmac", ""),
            "sig": item.get("message_sig", ""),
            "pubkey": item.get("message_pubkey", ""),
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
    """返回包含在线/离线状态的完整联系人列表"""
    ticket = _decrypt_valid_service_ticket(message)
    revoked = _revoked_session_error(message, ticket, address)
    if revoked:
        return revoked
    _update_user_last_seen(ticket.client_id, address[0])
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
    """验证操作者是管理员后禁言指定用户"""
    ticket = _decrypt_valid_service_ticket(message)
    revoked = _revoked_session_error(message, ticket, address)
    if revoked:
        return revoked
    _update_user_last_seen(ticket.client_id, address[0])
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
    """管理员验证通过后撤销用户的禁言规则"""
    ticket = _decrypt_valid_service_ticket(message)
    revoked = _revoked_session_error(message, ticket, address)
    if revoked:
        return revoked
    _update_user_last_seen(ticket.client_id, address[0])
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
    """从ChatServer的内存在线表中移除指定用户"""
    ticket = _decrypt_valid_service_ticket(message)
    revoked = _revoked_session_error(message, ticket, address)
    if revoked:
        return revoked
    _update_user_last_seen(ticket.client_id, address[0])
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
    dao.add_session_revocation(target, ticket.client_id, "管理员撤销会话")
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
    """返回聊天消息供管理员查看"""
    ticket = _decrypt_valid_service_ticket(message)
    revoked = _revoked_session_error(message, ticket, address)
    if revoked:
        return revoked
    _update_user_last_seen(ticket.client_id, address[0])
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
    """返回ChatServer审计日志供管理员查看"""
    ticket = _decrypt_valid_service_ticket(message)
    revoked = _revoked_session_error(message, ticket, address)
    if revoked:
        return revoked
    _update_user_last_seen(ticket.client_id, address[0])
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
    """更新ChatServer本地用户角色"""
    ticket = _decrypt_valid_service_ticket(message)
    revoked = _revoked_session_error(message, ticket, address)
    if revoked:
        return revoked
    _update_user_last_seen(ticket.client_id, address[0])
    if not _verify_admin_request(message, ticket):
        return Message(type="ERROR", seq=message["seq"], body={"error": "admin permission required"})
    target = message["body"].get("target_username", "")
    role = message["body"].get("role", "user")
    if role not in {"user", "admin"}:
        return Message(type="ERROR", seq=message["seq"], body={"error": "invalid role"})
    with dao._connect() as conn:
        now = int(time.time() * 1000)
        conn.execute(
            """
            INSERT INTO users (username, password_hash, password_plain, salt, role, created_at)
            VALUES (?, '', '', '', ?, ?)
            ON CONFLICT(username) DO UPDATE SET role = excluded.role
            """,
            (target, role, now),
        )
        conn.commit()
    dao.add_audit_log("", ticket.client_id, address[0], "CHAT_ADMIN_SET_ROLE", content_enc=json.dumps({"target": target, "role": role}, ensure_ascii=False))
    return Message(type="CHAT_ADMIN_ACK", seq=message["seq"], body={"updated": target, "role": role})


def _handle_chat_admin_delete_user(message: dict, address: tuple[str, int]) -> Message:
    """删除ChatServer本地联系人副本，保留聊天历史"""
    ticket = _decrypt_valid_service_ticket(message)
    revoked = _revoked_session_error(message, ticket, address)
    if revoked:
        return revoked
    _update_user_last_seen(ticket.client_id, address[0])
    if not _verify_admin_request(message, ticket):
        return Message(type="ERROR", seq=message["seq"], body={"error": "admin permission required"})
    target = message["body"].get("target_username", "").strip()
    if not target:
        return Message(type="ERROR", seq=message["seq"], body={"error": "target_username is required"})
    with online_lock:
        online_users.pop(target, None)
    dao.add_session_revocation(target, ticket.client_id, "用户已被管理员删除")
    deleted = dao.delete_user(target)
    dao.add_audit_log("", ticket.client_id, address[0], "CHAT_ADMIN_DELETE_USER", content_enc=json.dumps({"target": target, "deleted": deleted}, ensure_ascii=False))
    return Message(type="CHAT_ADMIN_ACK", seq=message["seq"], body={"target_username": target, "deleted": deleted})


def _decrypt_valid_service_ticket(message: dict):
    chat = dao.get_service(CHAT_SERVICE)
    if not chat:
        raise ValueError("ChatServer service is not configured")
    body = message.get("body", {})
    ticket = decrypt_ticket(body.get("ticket_v", body.get("service_ticket", {})), chat["service_key"])
    if not ticket.is_valid():
        raise ValueError(f"service ticket is expired: {ticket.validity_debug()}")
    return ticket


def _revoked_session_error(message: dict, ticket, address: tuple[str, int]) -> Message | None:
    """拒绝使用被管理员撤销的会话的请求"""
    revocation = dao.get_active_session_revocation(ticket.client_id)
    if not revocation:
        return None
    with online_lock:
        online_users.pop(ticket.client_id, None)
    reason = revocation.get("reason") or "会话已被管理员撤销"
    dao.add_audit_log(
        "",
        ticket.client_id,
        address[0],
        "CHAT_SESSION_REVOKED",
        content_enc=json.dumps({"reason": reason, "revoked_at": revocation.get("revoked_at", 0)}, ensure_ascii=False),
    )
    return Message(
        type="ERROR",
        seq=message["seq"],
        body={
            "error": f"session revoked; please re-login: {reason}",
            "code": "SESSION_REVOKED",
        },
    )


def _append_chat_message(sender: str, text: str, chat_type: str, recipient: str, image_data: str = "", file_name: str = "") -> int:
    session_key = _session_key(sender, chat_type, recipient)
    # message_hmac/message_sig/message_pubkey are optional; callers may pass via kwargs
    return dao.store_chat_message(
        sender=sender,
        recipient=recipient,
        chat_type=chat_type,
        session_key=session_key,
        message_text=text,
        message_hmac="",
        message_sig="",
        message_pubkey="",
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
            "status": "online",
        }


def _update_user_last_seen(username: str, client_ip: str = "") -> None:
    """更新用户最后活跃时间戳以保持在线状态"""
    with online_lock:
        if username in online_users:
            online_users[username]["last_seen"] = int(time.time() * 1000)
            if client_ip:
                online_users[username]["client_ip"] = client_ip
        else:
            online_users[username] = {
                "username": username,
                "session_id": "",
                "client_ip": client_ip,
                "last_seen": int(time.time() * 1000),
                "status": "online",
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


def _current_contact_users() -> list[dict]:
    """将持久化用户目录与当前ChatServer在线状态合并"""
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
                "status": "offline",
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
    """启动聊天服务器"""
    db_path = ensure_database("chat")
    host, port = server_bind_address("chat_server")
    public_host, public_port = service_address("chat_server")
    print(f"Starting ChatServer on {host}:{port}")
    print(f"ChatServer public address: {public_host}:{public_port}")
    print(f"ChatServer database: {db_path}")
    serve(host, port, "ChatServer", handle_message)


if __name__ == "__main__":
    main()
