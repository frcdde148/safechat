"""TGS票据授予服务器入口文件"""

from __future__ import annotations
import uuid

from common.config.settings import server_bind_address, service_address
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


def _require_admin(message: dict) -> tuple[bool, str]:
    body = message.get("body", {})
    payload = verify_admin_token(body.get("admin_token", ""))
    if not payload:
        return False, ""
    username = str(payload.get("username", ""))
    return bool(username), username


def _handle_admin_message(message: dict, address: tuple[str, int]) -> dict:
    ok, admin_user = _require_admin(message)
    if not ok:
        tgs_server.dao.add_audit_log("", admin_user or "unknown", address[0], "TGS_ADMIN_DENIED")
        return _admin_error(message, "需要管理员权限")
    body = message.get("body", {})
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

