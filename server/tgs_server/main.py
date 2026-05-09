"""TGS server entry point."""

from __future__ import annotations
import uuid

from common.config.settings import server_bind_address, service_address
from common.protocol.admin_token import verify_admin_token
from database.init_db import ensure_database
from server.simple_tcp_server import serve
from server.tgs_server.core import TicketGrantingServer

# Initialize Ticket Granting Server instance
tgs_server = TicketGrantingServer()

PROTOCOL_VERSION = "safechat-kerberos-v4-ext"


def handle_message(message: dict, address: tuple[str, int]) -> dict:
    """Handle Client -> TGS service-ticket requests and return response dict."""
    if message["type"].startswith("TGS_ADMIN_"):
        return _handle_admin_message(message, address)

    # Validate message type
    if message["type"] != "C_TGS_REQ":
        return {
            "type": "ERROR",
            "seq": message["seq"],
            "body": {"error": "TGS only accepts C_TGS_REQ messages"},
            "sid": message.get("sid", ""),
            "v": 1,
            "ts": message.get("ts", 0),
            "nonce": message.get("nonce", ""),
            "hmac": "",
            "sig": "",
            "pubkey": "",
        }
    
    # Extract request parameters
    ticket_tgt = message["body"].get("ticket_tgt", {})
    authenticator = message["body"].get("authenticator", {})
    client_addr = address[0]
    message_body = message.get("body", {})
    message_hmac = message.get("hmac", "")
    message_sig = message.get("sig", "")
    message_pubkey = message.get("pubkey", "")
    
    # Request service ticket
    response = tgs_server.request_service_ticket(ticket_tgt, authenticator, client_addr, 
                                                 message_body, message_hmac, message_sig, message_pubkey)
    
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
        "service_ticket": response.service_ticket,
        "chat_host": response.chat_host,
        "chat_port": response.chat_port,
        "version": PROTOCOL_VERSION,
        "request_id": str(uuid.uuid4()),
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
        "pubkey": "",
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
        return _admin_error(message, "admin permission required")
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
    return _admin_error(message, f"unknown TGS admin action: {message['type']}")


def main() -> None:
    """Start the ticket granting server."""
    db_path = ensure_database("tgs")
    host, port = server_bind_address("tgs_server")
    public_host, public_port = service_address("tgs_server")
    print(f"Starting TGS server on {host}:{port}")
    print(f"TGS public address: {public_host}:{public_port}")
    print(f"TGS database: {db_path}")
    serve(host, port, "TGS Server", handle_message)


if __name__ == "__main__":
    main()

