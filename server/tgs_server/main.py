"""TGS server entry point."""

from __future__ import annotations

import json
import uuid

from common.config.settings import server_bind_address
from server.tgs_server.core import TicketGrantingServer

# Initialize Ticket Granting Server instance
tgs_server = TicketGrantingServer()

PROTOCOL_VERSION = "safechat-kerberos-v4-ext"


def handle_message(message: dict, address: tuple[str, int]) -> dict:
    """Handle Client -> TGS service-ticket requests and return response dict."""
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
    
    # Sign the response
    digest, signature = tgs_server.sign_response(response_body)
    
    # Return signed response as dict
    return {
        "type": "TGS_C_REP",
        "seq": message["seq"],
        "body": response_body,
        "sid": message.get("sid", ""),
        "v": 1,
        "ts": message.get("ts", 0),
        "nonce": message.get("nonce", ""),
        "hmac": digest,
        "sig": signature,
        "pubkey": tgs_server.get_public_key(),
    }


def main() -> None:
    """Start the ticket granting server."""
    host, port = server_bind_address("tgs_server")
    print(f"Starting TGS server on {host}:{port}")
    
    # Custom serve function that handles dict messages
    import socket
    import struct
    
    def custom_serve(host: str, port: int, server_name: str, handler):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(5)
            print(f"{server_name} listening on {host}:{port}")
            
            while True:
                conn, addr = sock.accept()
                with conn:
                    try:
                        # Read length
                        length_data = conn.recv(4)
                        if not length_data:
                            continue
                        length = struct.unpack('!I', length_data)[0]
                        
                        # Read message
                        data = b''
                        while len(data) < length:
                            chunk = conn.recv(min(length - len(data), 4096))
                            if not chunk:
                                break
                            data += chunk
                        
                        # Parse and handle
                        message = json.loads(data.decode('utf-8'))
                        response = handler(message, addr)
                        
                        # Send response
                        response_json = json.dumps(response)
                        conn.sendall(struct.pack('!I', len(response_json)))
                        conn.sendall(response_json.encode('utf-8'))
                    except Exception as e:
                        print(f"Error handling connection: {e}")
    
    custom_serve(host, port, "TGS Server", handle_message)


if __name__ == "__main__":
    main()

