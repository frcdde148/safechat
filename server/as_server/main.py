"""AS server entry point."""

from __future__ import annotations

import secrets

from common.config.settings import server_bind_address
from common.models.tickets import encrypt_model, issue_ticket
from common.protocol.message import Message
from database.dao.sqlite_dao import SQLiteDAO
from server.simple_tcp_server import serve


TGS_SERVICE = "tgs_server"


dao = SQLiteDAO()


def handle_message(message: dict, address: tuple[str, int]) -> Message:
    """Handle Client -> AS requests."""
    if message["type"] != "C_AS_REQ":
        return Message(type="ERROR", seq=message["seq"], body={"error": "AS only accepts C_AS_REQ"})

    username = message["body"].get("username", "")
    password = message["body"].get("password", "")
    client_addr = address[0]
    if dao.is_ip_banned(client_addr):
        return Message(type="ERROR", seq=message["seq"], body={"error": "client IP is banned"})
    if not dao.verify_user_password(username, password):
        dao.add_audit_log("", username or "unknown", client_addr, "LOGIN_FAILED")
        return Message(type="ERROR", seq=message["seq"], body={"error": "invalid username or password"})

    # Check for existing active session (Single Sign-On control)
    existing_session = dao.get_active_session(username)
    if existing_session:
        existing_ip = existing_session["client_ip"]
        if existing_ip != client_addr:
            dao.add_audit_log("", username, client_addr, "LOGIN_DENIED_DUPLICATE")
            return Message(
                type="ERROR",
                seq=message["seq"],
                body={"error": f"user {username} is already logged in from {existing_ip}"},
            )

    service = dao.get_service(TGS_SERVICE)
    if not service:
        return Message(type="ERROR", seq=message["seq"], body={"error": "TGS service is not configured"})

    session_key = secrets.token_hex(16)
    tgt = issue_ticket(username, client_addr, session_key, TGS_SERVICE)
    encrypted_tgt = encrypt_model(tgt, service["service_key"])

    # Create session record (invalidates any existing sessions)
    session_id = secrets.token_hex(32)
    dao.create_session(username, session_id, client_addr, tgt.issued_at, tgt.expires_at)

    dao.add_audit_log(session_id, username, client_addr, "LOGIN_AS_OK")
    return Message(
        type="AS_C_REP",
        seq=message["seq"],
        body={
            "client_id": username,
            "session_key_c_tgs": session_key,
            "ticket_tgt": encrypted_tgt,
            "tgs_host": service["service_host"],
            "tgs_port": service["service_port"],
            "session_id": session_id,
        },
    )


def main() -> None:
    """Start the authentication server."""
    host, port = server_bind_address("as_server")
    serve(host, port, "AS server", handle_message)


if __name__ == "__main__":
    main()
