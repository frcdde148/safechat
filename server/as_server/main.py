"""AS server entry point."""

from __future__ import annotations

import uuid
import json

from common.config.settings import server_bind_address
from server.as_server.core import AuthenticationServer
from server.simple_tcp_server import serve

# Initialize Authentication Server instance
as_server = AuthenticationServer()

PROTOCOL_VERSION = "safechat-kerberos-v4-ext"


def handle_message(message: dict, address: tuple[str, int]) -> dict:
    """Handle Client -> AS requests and return response dict."""
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
    password = message["body"].get("password", "")
    client_addr = address[0]
    
    # Perform authentication
    response = as_server.authenticate(username, password, client_addr)
    
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
        "session_key_c_tgs": response.session_key_c_tgs,
        "ticket_tgt": response.ticket_tgt,
        "tgs_host": response.tgs_host,
        "tgs_port": response.tgs_port,
        "version": PROTOCOL_VERSION,
        "request_id": str(uuid.uuid4()),
    }
    
    # Sign the response
    digest, signature = as_server.sign_response(response_body)
    
    # Return signed response as dict
    return {
        "type": "AS_C_REP",
        "seq": message["seq"],
        "body": response_body,
        "sid": message.get("sid", ""),
        "v": 1,
        "ts": message.get("ts", 0),
        "nonce": message.get("nonce", ""),
        "hmac": digest,
        "sig": signature,
        "pubkey": as_server.get_public_key(),
    }


def main() -> None:
    """Start the authentication server."""
    host, port = server_bind_address("as_server")
    print(f"Starting AS server on {host}:{port}")
    
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
    
    custom_serve(host, port, "AS Server", handle_message)


if __name__ == "__main__":
    main()