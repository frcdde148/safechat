"""AS server entry point."""

from __future__ import annotations

import uuid
import json
import time
import re

from common.config.settings import server_bind_address, service_address
from common.protocol.admin_token import issue_admin_token, verify_admin_token
from common.models.tickets import decrypt_authenticator, decrypt_ticket
from database.init_db import ensure_database
from server.as_server.core import AuthenticationServer
from server.simple_tcp_server import serve

# Initialize Authentication Server instance
as_server = AuthenticationServer()

PROTOCOL_VERSION = "safechat-kerberos-v4-ext"


def handle_message(message: dict, address: tuple[str, int]) -> dict:
    """Handle Client -> AS requests and return response dict."""
    if message["type"].startswith("AS_ADMIN_"):
        return _handle_admin_message(message, address)

    if message["type"] == "AS_SESSION_HEARTBEAT":
        return _handle_session_heartbeat(message, address)

    # Validate message type
    if message["type"] != "C_AS_REQ":
        return {
            "type": "ERROR",
            "seq": message["seq"],
            "body": {"error": "AS only accepts C_AS_REQ messages"},
            "sid": message.get("sid", ""),
            "v": 1,
            "ts": message.get("ts", 0),
            "nonce": message.get("nonce", ""),
            "hmac": "",
            "sig": "",
            "pubkey": "",
        }
    
    # Extract credentials from request
    username = message["body"].get("username", "")
    client_addr = address[0]
    message_body = message.get("body", {})
    message_hmac = message.get("hmac", "")
    message_sig = message.get("sig", "")
    message_pubkey = message.get("pubkey", "")
    
    # Perform authentication
    response = as_server.authenticate(username, client_addr, message_body, message_hmac, message_sig, message_pubkey)
    
    if not response.success:
        return {
            "type": "ERROR",
            "seq": message["seq"],
            "body": {"error": response.error},
            "sid": message.get("sid", ""),
            "v": 1,
            "ts": message.get("ts", 0),
            "nonce": message.get("nonce", ""),
            "hmac": "",
            "sig": "",
            "pubkey": "",
        }
    
    # Build response body with ALL required fields
    response_body = {
        "client_id": response.client_id,
        "encrypted_session_key": response.encrypted_session_key,
        "client_part": response.encrypted_session_key,
        "ticket_tgt": response.ticket_tgt,
        "salt": response.salt,
        "tgs_host": response.tgs_host,
        "tgs_port": response.tgs_port,
        "version": PROTOCOL_VERSION,
        "request_id": str(uuid.uuid4()),
        "session_id": response.session_id,
    }
    return _envelope(message, "AS_C_REP", response_body)


def _envelope(message: dict, response_type: str, body: dict) -> dict:
    return {
        "type": response_type,
        "seq": message["seq"],
        "body": body,
        "sid": message.get("sid", ""),
        "v": 1,
        "ts": message.get("ts", 0),
        "nonce": message.get("nonce", ""),
        "hmac": "",
        "sig": "",
        "pubkey": "",
    }


def _admin_error(message: dict, error: str) -> dict:
    return _envelope(message, "ERROR", {"error": error})


def _require_admin(message: dict) -> tuple[bool, str]:
    body = message.get("body", {})
    token = body.get("admin_token", "")
    payload = verify_admin_token(token)
    if not payload:
        return False, ""
    username = str(payload.get("username", ""))
    user = as_server.dao.get_user(username)
    return bool(user and user.get("role") == "admin"), username


def _handle_admin_message(message: dict, address: tuple[str, int]) -> dict:
    if message["type"] == "AS_ADMIN_TOKEN_REQ":
        return _handle_admin_token_req(message, address)
    ok, admin_user = _require_admin(message)
    if not ok:
        as_server.dao.add_audit_log("", admin_user or "unknown", address[0], "AS_ADMIN_DENIED")
        return _admin_error(message, "admin permission required")
    body = message.get("body", {})
    action = message["type"]
    dao = as_server.dao
    try:
        if action == "AS_ADMIN_LIST_USERS":
            with dao._connect() as conn:
                rows = conn.execute(
                    "SELECT username, role, created_at FROM users ORDER BY username"
                ).fetchall()
                return _envelope(message, "AS_ADMIN_ACK", {"users": [dict(row) for row in rows]})
        if action == "AS_ADMIN_CREATE_USER":
            username = str(body.get("username", "")).strip()
            password = str(body.get("password", ""))
            role = str(body.get("role", "user"))
            error = _validate_user_fields(username, password, role)
            if error:
                return _admin_error(message, error)
            if dao.get_user(username):
                return _admin_error(message, "用户名已存在")
            dao.create_user(username, password, role)
            dao.add_audit_log("", admin_user, address[0], "AS_ADMIN_CREATE_USER", json.dumps({"target": username, "role": role}, ensure_ascii=False))
            return _envelope(message, "AS_ADMIN_ACK", {"username": username, "role": role})
        if action == "AS_ADMIN_DELETE_USER":
            target = str(body.get("target_username", "")).strip()
            if not target:
                return _admin_error(message, "目标用户名不能为空")
            target_user = dao.get_user(target)
            if not target_user:
                return _admin_error(message, "目标用户不存在")
            if target == admin_user:
                return _admin_error(message, "不能删除当前管理员自己")
            if target_user.get("role") == "admin" and dao.count_admin_users() <= 1:
                return _admin_error(message, "至少需要保留一个管理员")
            dao.delete_user(target)
            dao.add_audit_log("", admin_user, address[0], "AS_ADMIN_DELETE_USER", target)
            return _envelope(message, "AS_ADMIN_ACK", {"target_username": target})
        if action == "AS_ADMIN_SET_ROLE":
            target = body.get("target_username", "")
            role = body.get("role", "user")
            if role not in {"user", "admin"}:
                return _admin_error(message, "角色无效")
            target_user = dao.get_user(target)
            if not target_user:
                return _admin_error(message, "目标用户不存在")
            if target == admin_user:
                return _admin_error(message, "不能修改当前管理员自己的角色")
            if target_user.get("role") == "admin" and role == "user" and dao.count_admin_users() <= 1:
                return _admin_error(message, "至少需要保留一个管理员")
            with dao._connect() as conn:
                conn.execute("UPDATE users SET role = ? WHERE username = ?", (role, target))
                conn.commit()
            dao.add_audit_log("", admin_user, address[0], "AS_ADMIN_SET_ROLE", json.dumps({"target": target, "role": role}, ensure_ascii=False))
            return _envelope(message, "AS_ADMIN_ACK", {"updated": target, "role": role})
        if action == "AS_ADMIN_RESET_PASSWORD":
            target = str(body.get("target_username", "")).strip()
            password = str(body.get("password", ""))
            if not target:
                return _admin_error(message, "目标用户名不能为空")
            if len(password) < 6:
                return _admin_error(message, "密码长度至少为 6 位")
            if not dao.update_user_password(target, password):
                return _admin_error(message, "目标用户不存在")
            dao.invalidate_user_sessions(target)
            dao.add_audit_log("", admin_user, address[0], "AS_ADMIN_RESET_PASSWORD", target)
            return _envelope(message, "AS_ADMIN_ACK", {"target_username": target})
        if action == "AS_ADMIN_LIST_SESSIONS":
            with dao._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT username, session_id, client_ip, tgt_issued_at, tgt_expires_at,
                           service_ticket_issued_at, service_ticket_expires_at, last_seen, status
                    FROM active_sessions
                    ORDER BY id DESC
                    LIMIT 300
                    """
                ).fetchall()
                return _envelope(message, "AS_ADMIN_ACK", {"sessions": [dict(row) for row in rows]})
        if action == "AS_ADMIN_INVALIDATE_USER":
            target = body.get("target_username", "")
            dao.invalidate_user_sessions(target)
            dao.add_audit_log("", admin_user, address[0], "AS_ADMIN_INVALIDATE_USER", target)
            return _envelope(message, "AS_ADMIN_ACK", {"target_username": target})
        if action == "AS_ADMIN_BAN_IP":
            ip = dao._normalize_ip(body.get("ip_address", ""))
            reason = body.get("reason", "")
            ban_seconds = int(body.get("ban_seconds", 1800))
            if ban_seconds <= 0:
                return _admin_error(message, "ban_seconds must be positive")
            with dao._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO ip_bans (ip_address, reason, ban_time, created_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(ip_address) DO UPDATE SET
                        reason = excluded.reason,
                        ban_time = excluded.ban_time,
                        created_at = excluded.created_at
                    """,
                    (ip, reason, ban_seconds, int(time.time() * 1000)),
                )
                conn.commit()
            dao.add_audit_log("", admin_user, address[0], "AS_ADMIN_BAN_IP", json.dumps({"ip": ip, "seconds": ban_seconds}, ensure_ascii=False))
            return _envelope(message, "AS_ADMIN_ACK", {"ip_address": ip})
        if action == "AS_ADMIN_UNBAN_IP":
            ip = dao._normalize_ip(body.get("ip_address", ""))
            if not ip:
                return _admin_error(message, "ip_address is required")
            with dao._connect() as conn:
                rows = conn.execute("SELECT id, ip_address FROM ip_bans").fetchall()
                ids = [int(row["id"]) for row in rows if dao._normalize_ip(row["ip_address"]) == ip]
                if ids:
                    placeholders = ",".join("?" for _ in ids)
                    cursor = conn.execute(f"DELETE FROM ip_bans WHERE id IN ({placeholders})", ids)
                else:
                    cursor = conn.execute("DELETE FROM ip_bans WHERE ip_address = ?", (ip,))
                conn.commit()
            dao.add_audit_log("", admin_user, address[0], "AS_ADMIN_UNBAN_IP", json.dumps({"ip": ip, "deleted": cursor.rowcount}, ensure_ascii=False))
            return _envelope(message, "AS_ADMIN_ACK", {"ip_address": ip, "deleted": int(cursor.rowcount)})
        if action == "AS_ADMIN_LIST_IP_BANS":
            with dao._connect() as conn:
                rows = conn.execute(
                    "SELECT id, ip_address, reason, ban_time, created_at FROM ip_bans ORDER BY id DESC LIMIT 200"
                ).fetchall()
                now_ms = int(time.time() * 1000)
                bans = []
                for row in rows:
                    item = dict(row)
                    created_at = int(item.get("created_at", 0) or 0)
                    if created_at < 10_000_000_000:
                        created_at *= 1000
                    expires_at = created_at + int(item.get("ban_time", 0) or 0) * 1000
                    item["created_at"] = created_at
                    item["expires_at"] = expires_at
                    item["active"] = expires_at >= now_ms
                    bans.append(item)
                return _envelope(message, "AS_ADMIN_ACK", {"ip_bans": bans})
        if action == "AS_ADMIN_AUDIT_QUERY":
            action_filter = body.get("action_filter", "")
            params = []
            query = "SELECT id, timestamp, user_id, client_ip, action_type, content_enc, signature FROM audit_logs"
            if action_filter:
                query += " WHERE action_type LIKE ?"
                params.append(f"%{action_filter}%")
            query += " ORDER BY id DESC LIMIT ?"
            params.append(int(body.get("limit", 300)))
            with dao._connect() as conn:
                rows = conn.execute(query, params).fetchall()
                return _envelope(message, "AS_ADMIN_ACK", {"audit_logs": [dict(row) for row in rows]})
    except Exception as exc:
        return _admin_error(message, str(exc))
    return _admin_error(message, f"unknown AS admin action: {action}")


def _handle_session_heartbeat(message: dict, address: tuple[str, int]) -> dict:
    body = message.get("body", {})
    username = str(body.get("username", ""))
    session_id = str(body.get("session_id", ""))
    if not username or not session_id:
        return _admin_error(message, "username and session_id are required")
    session = as_server.dao.get_active_session(username, "client")
    if not session or session.get("session_id") != session_id:
        return _admin_error(message, "session is not active")
    if as_server.dao._normalize_ip(session.get("client_ip", "")) != as_server.dao._normalize_ip(address[0]):
        return _admin_error(message, "session address mismatch")
    as_server.dao.update_session_last_seen(session_id)
    return _envelope(message, "AS_SESSION_HEARTBEAT_ACK", {"ok": True})


def _validate_user_fields(username: str, password: str, role: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_]{3,32}", username):
        return "用户名必须为 3-32 位字母、数字或下划线"
    if len(password) < 6:
        return "密码长度至少为 6 位"
    if role not in {"user", "admin"}:
        return "角色无效"
    return ""


def _handle_admin_token_req(message: dict, address: tuple[str, int]) -> dict:
    """Issue an admin token after validating the existing Kerberos TGT."""
    dao = as_server.dao
    try:
        tgs_service = dao.get_service(as_server.TGS_SERVICE)
        if not tgs_service:
            return _admin_error(message, "TGS service is not configured")
        tgt = decrypt_ticket(message["body"]["ticket_tgt"], tgs_service["service_key"])
        if not tgt.is_valid():
            return _admin_error(message, f"TGT is expired: {tgt.validity_debug()}")
        authenticator = decrypt_authenticator(message["body"]["authenticator"], tgt.session_key)
        if authenticator.client_id != tgt.client_id:
            return _admin_error(message, "authenticator client does not match TGT")
        if authenticator.client_addr and authenticator.client_addr != tgt.client_addr:
            return _admin_error(message, "authenticator does not match TGT client address")
        user = dao.get_user(tgt.client_id)
        if not user or user.get("role") != "admin":
            dao.add_audit_log("", tgt.client_id, address[0], "AS_ADMIN_TOKEN_DENIED")
            return _admin_error(message, "admin permission required")
        token = issue_admin_token(tgt.client_id)
        dao.add_audit_log("", tgt.client_id, address[0], "AS_ADMIN_TOKEN_OK")
        return _envelope(message, "AS_ADMIN_ACK", {"admin_token": token, "expires_in": 3600})
    except Exception as exc:
        return _admin_error(message, str(exc))


def main() -> None:
    """Start the authentication server."""
    db_path = ensure_database("as")
    host, port = server_bind_address("as_server")
    public_host, public_port = service_address("as_server")
    print(f"Starting AS server on {host}:{port}")
    print(f"AS public address: {public_host}:{public_port}")
    print(f"AS database: {db_path}")
    serve(host, port, "AS Server", handle_message)


if __name__ == "__main__":
    main()
