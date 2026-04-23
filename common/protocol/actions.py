"""Protocol message types and security levels shared by clients and servers."""

CONTROL_TYPES = {
    "HEARTBEAT",
    "HEARTBEAT_ACK",
    "ERROR",
    "VERSION_NEG",
}

AUTH_TYPES = {
    "C_AS_REQ",
    "AS_C_REP",
    "C_TGS_REQ",
    "TGS_C_REP",
    "C_V_REQ",
    "V_C_REP",
}

DATA_TYPES = {
    "CHAT_SEND",
    "CHAT_RECV",
    "CHAT_ACK",
    "USER_LIST",
    "USER_ONLINE",
    "USER_OFFLINE",
    "FILE_SEND_REQ",
    "FILE_SEND_DATA",
    "FILE_RECV_NOTIFY",
    "FILE_RECV_DATA",
    "FILE_ACK",
    "FILE_SEND_ACK",
}

ALL_TYPES = CONTROL_TYPES | AUTH_TYPES | DATA_TYPES

ENCRYPTED_TYPES = DATA_TYPES
HMAC_TYPES = DATA_TYPES
SIGNED_TYPES = {
    "CHAT_SEND",
    "CHAT_RECV",
    "CHAT_ACK",
}

TYPE_LAYER = {
    **{msg_type: "control" for msg_type in CONTROL_TYPES},
    **{msg_type: "auth" for msg_type in AUTH_TYPES},
    **{msg_type: "data" for msg_type in DATA_TYPES},
}

SECURITY_LEVELS = {
    msg_type: {
        "encrypted": msg_type in ENCRYPTED_TYPES,
        "hmac": msg_type in HMAC_TYPES,
        "signature": msg_type in SIGNED_TYPES,
    }
    for msg_type in ALL_TYPES
}
