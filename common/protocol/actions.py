"""客户端与服务器共享的协议消息类型和安全等级定义。"""

CONTROL_TYPES = {
    "HEARTBEAT",
    "ERROR",
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
    "CHAT_POLL",
    "CHAT_RECV",
    "CHAT_ACK",
    "USER_LIST",
    "ADMIN_MUTE_USER",
    "ADMIN_MUTE_ACK",
    "ADMIN_UNMUTE_USER",
    "ADMIN_UNMUTE_ACK",
    "ADMIN_KICK_USER",
    "ADMIN_KICK_ACK",
    "AS_ADMIN_LIST_USERS",
    "AS_ADMIN_TOKEN_REQ",
    "AS_ADMIN_CREATE_USER",
    "AS_ADMIN_DELETE_USER",
    "AS_ADMIN_SET_ROLE",
    "AS_ADMIN_RESET_PASSWORD",
    "AS_ADMIN_LIST_SESSIONS",
    "AS_ADMIN_INVALIDATE_USER",
    "AS_ADMIN_BAN_IP",
    "AS_ADMIN_UNBAN_IP",
    "AS_ADMIN_LIST_IP_BANS",
    "AS_ADMIN_AUDIT_QUERY",
    "AS_ADMIN_ACK",
    "AS_SESSION_HEARTBEAT",
    "AS_SESSION_HEARTBEAT_ACK",
    "TGS_ADMIN_AUDIT_QUERY",
    "TGS_ADMIN_ACK",
    "CHAT_ADMIN_LIST_MESSAGES",
    "CHAT_ADMIN_AUDIT_QUERY",
    "CHAT_ADMIN_SET_ROLE",
    "CHAT_ADMIN_DELETE_USER",
    "CHAT_ADMIN_ACK",
    "IMAGE_SEND",
    "IMAGE_FETCH",
}

ALL_TYPES = CONTROL_TYPES | AUTH_TYPES | DATA_TYPES

ENCRYPTED_TYPES = DATA_TYPES
HMAC_TYPES = DATA_TYPES
SIGNED_TYPES = {
    "CHAT_SEND",
    "CHAT_POLL",
    "USER_LIST",
    "IMAGE_SEND",
    "IMAGE_FETCH",
    "ADMIN_MUTE_USER",
    "ADMIN_UNMUTE_USER",
    "ADMIN_KICK_USER",
    "CHAT_ADMIN_LIST_MESSAGES",
    "CHAT_ADMIN_AUDIT_QUERY",
    "CHAT_ADMIN_SET_ROLE",
    "CHAT_ADMIN_DELETE_USER",
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
