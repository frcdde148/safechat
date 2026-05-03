"""TGS server entry point."""

from __future__ import annotations

import secrets

from common.models.tickets import decrypt_authenticator, decrypt_ticket, encrypt_model, issue_ticket
from common.protocol.message import Message
from database.dao.sqlite_dao import SQLiteDAO
from server.simple_tcp_server import serve


HOST = "127.0.0.1"
PORT = 8001
TGS_SERVICE = "tgs_server"
CHAT_SERVICE = "chat_server"


dao = SQLiteDAO()


def handle_message(message: dict, address: tuple[str, int]) -> Message:
    """Handle Client -> TGS service-ticket requests."""
    if message["type"] != "C_TGS_REQ":
        return Message(type="ERROR", seq=message["seq"], body={"error": "TGS only accepts C_TGS_REQ"})

    tgs = dao.get_service(TGS_SERVICE)
    chat = dao.get_service(CHAT_SERVICE)
    if not tgs or not chat:
        return Message(type="ERROR", seq=message["seq"], body={"error": "service configuration is incomplete"})

    tgt = decrypt_ticket(message["body"]["ticket_tgt"], tgs["service_key"])
    if not tgt.is_valid():
        return Message(type="ERROR", seq=message["seq"], body={"error": "TGT is expired"})
    authenticator = decrypt_authenticator(message["body"]["authenticator"], tgt.session_key)
    if authenticator.client_id != tgt.client_id:
        return Message(type="ERROR", seq=message["seq"], body={"error": "authenticator client does not match TGT"})
    if authenticator.client_addr and authenticator.client_addr != tgt.client_addr:
        return Message(type="ERROR", seq=message["seq"], body={"error": "authenticator does not match TGT"})

    session_key = secrets.token_hex(16)
    service_ticket = issue_ticket(tgt.client_id, tgt.client_addr, session_key, CHAT_SERVICE)
    dao.add_audit_log("", tgt.client_id, address[0], "TGS_TICKET_OK")
    return Message(
        type="TGS_C_REP",
        seq=message["seq"],
        body={
            "client_id": tgt.client_id,
            "session_key_c_v": session_key,
            "service_ticket": encrypt_model(service_ticket, chat["service_key"]),
            "chat_host": chat["service_host"],
            "chat_port": chat["service_port"],
        },
    )


def main() -> None:
    """Start the ticket granting server."""
    serve(HOST, PORT, "TGS server", handle_message)


if __name__ == "__main__":
    main()
