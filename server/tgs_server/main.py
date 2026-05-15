"""TGS票据授予服务器入口文件"""

from __future__ import annotations
import json
import uuid

from common.config.settings import server_bind_address, service_address
from common.crypto.des import decrypt_text
from common.models.tickets import decrypt_authenticator, decrypt_ticket
from common.protocol.admin_token import verify_admin_token
from database.init_db import ensure_database
from server.simple_tcp_server import serve
from server.tgs_server.core import TicketGrantingServer

# 初始化票据授予服务器实例
tgs_server = TicketGrantingServer()

PROTOCOL_VERSION = "safechat-kerberos-v4-ext"


def handle_message(message: dict, address: tuple[str, int]) -> dict:
    """处理客户端到TGS服务器的服务票据请求并返回响应"""
    if message["type"].startswith("TGS_ADMIN_"):
        return _handle_admin_message(message, address)

    # 验证消息类型
    if message["type"] != "C_TGS_REQ":
        return {
            "type": "ERROR",
            "seq": message["seq"],
            "body": {"error": "TGS 仅接受 C_TGS_REQ 消息"},
            "sid": message.get("sid", ""),
            "v": 1,
            "ts": message.get("ts", 0),
            "nonce": message.get("nonce", ""),
            "hmac": "",
            "sig": "",
        }
    
    # 提取请求参数
    body = message.get("body", {})
    extensions = body.get("extensions", {}) if isinstance(body.get("extensions", {}), dict) else {}
    ticket_tgt = body.get("ticket_tgs", body.get("ticket_tgt", {}))
    authenticator = body.get("authenticator_c", body.get("authenticator", {}))
    client_addr = address[0]
    message_body = message.get("body", {})
    message_hmac = message.get("hmac", "")
    message_sig = message.get("sig", "")
    
    # 请求服务票据
    response = tgs_server.request_service_ticket(ticket_tgt, authenticator, client_addr, 
                                                 message_body, message_hmac, message_sig)
    
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
        }
    
    # 构建包含所有必需字段的响应体
    response_body = {
        "client_part": response.client_part,
        "extensions": response.extensions,
    }
    return _envelope(message, "TGS_C_REP", response_body)


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
    }


def _admin_error(message: dict, error: str) -> dict:
    return _envelope(message, "ERROR", {"error": error})


def _same_client_addr(left: str, right: str) -> bool:
    if not left or not right:
        return True
    left_local = left.startswith("127.") or left == "::1" or left == "localhost"
    right_local = right.startswith("127.") or right == "::1" or right == "localhost"
    return (left_local and right_local) or left == right


def _decrypt_admin_request(message: dict) -> tuple[str, dict]:
    body = message.get("body", {})
    ticket_tgs = body.get("ticket_tgs", body.get("ticket_tgt"))
    authenticator_enc = body.get("authenticator_c", body.get("authenticator"))
    admin_cipher = body.get("admin_cipher")
    if not ticket_tgs or not authenticator_enc or not admin_cipher:
        raise ValueError("TGS 管理请求必须使用加密格式")

    tgs_service = tgs_server.dao.get_service(tgs_server.TGS_SERVICE)
    if not tgs_service:
        raise ValueError("TGS 服务未配置")

    tgt = decrypt_ticket(ticket_tgs, tgs_service["service_key"])
    if not tgt.is_valid():
        raise ValueError(f"TGT 已过期：{tgt.validity_debug()}")

    authenticator = decrypt_authenticator(authenticator_enc, tgt.session_key)
    if authenticator.client_id != tgt.client_id:
        raise ValueError("认证器用户与 TGT 不匹配")
    if not _same_client_addr(authenticator.client_addr, tgt.client_addr):
        raise ValueError("认证器地址与 TGT 客户端地址不匹配")

    plaintext = decrypt_text(admin_cipher["ciphertext"], admin_cipher["iv"], tgt.session_key)
    payload = json.loads(plaintext)
    if payload.get("action_type") != message["type"]:
        raise ValueError("管理请求动作与密文内容不匹配")

    token_payload = verify_admin_token(payload.get("admin_token", ""))
    if not token_payload:
        raise ValueError("管理员令牌无效或已过期")
    username = str(token_payload.get("username", ""))
    if username != tgt.client_id:
        raise ValueError("管理员令牌与 TGT 用户不匹配")

    fields = payload.get("fields", {})
    if not isinstance(fields, dict):
        raise ValueError("管理请求字段格式无效")
    return username, fields


def _require_admin(message: dict) -> tuple[bool, str, dict]:
    username, fields = _decrypt_admin_request(message)
    return bool(username), username, fields


def _handle_admin_message(message: dict, address: tuple[str, int]) -> dict:
    try:
        ok, admin_user, body = _require_admin(message)
    except Exception as exc:
        tgs_server.dao.add_audit_log("", "unknown", address[0], "TGS_ADMIN_DENIED")
        return _admin_error(message, str(exc))
    if not ok:
        tgs_server.dao.add_audit_log("", admin_user or "unknown", address[0], "TGS_ADMIN_DENIED")
        return _admin_error(message, "需要管理员权限")
    try:
        if message["type"] == "TGS_ADMIN_AUDIT_QUERY":
            action_filter = body.get("action_filter", "")
            params = []
            query = "SELECT id, timestamp, user_id, client_ip, action_type, content_enc, signature FROM audit_logs"
            if action_filter:
                query += " WHERE action_type LIKE ?"
                params.append(f"%{action_filter}%")
            query += " ORDER BY id DESC LIMIT ?"
            params.append(int(body.get("limit", 300)))
            with tgs_server.dao._connect() as conn:
                rows = conn.execute(query, params).fetchall()
                return _envelope(message, "TGS_ADMIN_ACK", {"audit_logs": [dict(row) for row in rows]})
    except Exception as exc:
        return _admin_error(message, str(exc))
    return _admin_error(message, f"未知 TGS 管理操作：{message['type']}")


def main() -> None:
    """启动票据授予服务器"""
    db_path = ensure_database("tgs")
    host, port = server_bind_address("tgs_server")
    public_host, public_port = service_address("tgs_server")
    print(f"Starting TGS server on {host}:{port}")
    print(f"TGS public address: {public_host}:{public_port}")
    print(f"TGS database: {db_path}")
    serve(host, port, "TGS Server", handle_message)


if __name__ == "__main__":
    main()

