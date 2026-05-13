"""客户端Kerberos认证模块

实现SafeChat六步Kerberos认证流程：
1. C_AS_REQ: 向AS请求TGT（票据授予票据）
2. AS_C_REP: AS返回TGT和会话密钥
3. C_TGS_REQ: 向TGS请求服务票据
4. TGS_C_REP: TGS返回服务票据和会话密钥
5. C_V_REQ: 向ChatServer请求认证
6. V_C_REP: 双向认证完成

登录后消息使用：DES加密 + HMAC + RSA签名
"""

from __future__ import annotations

import json
import time
from typing import Any

# 导入加密模块
from common.crypto.des import decrypt_text, encrypt_text
from common.crypto.rsa_sign import generate_key_pair
from common.crypto.sha256 import salted_password_hash, sha256_hex
from common.models.tickets import encrypt_authenticator, encrypt_model, issue_authenticator
from common.protocol.message import Message
from common.protocol.security import sign_body
from common.protocol.socket_io import request


class AuthClient:
    """Kerberos认证客户端 - 管理六步认证流程和消息收发"""

    def __init__(self, payload: dict[str, Any]) -> None:
        # 用户凭证（登录时输入）
        self.username = payload["username"]
        self.password = payload["password"]
        self.client_type = payload.get("client_type", "client")
        # 如果没有显式传入 client_addr，则尝试推断出站地址以与服务器看到的地址匹配
        self.client_addr = payload.get("client_addr", "")
        self.tgt_client_addr = ""  # 从 TGT 中保存的客户端地址（步骤3使用）
        self.service_ticket_client_addr = ""  # 从服务票据中保存的客户端地址（步骤5使用）
        
        # 服务器地址配置
        self.as_host, self.as_port = payload["as"]
        self.tgs_host = ""      # AS响应后填充
        self.tgs_port = 0
        self.chat_host = ""     # TGS响应后填充
        self.chat_port = 0
        
        # 消息序列号（防重放攻击）
        self.seq = 1
        
        # 票据相关
        self.tgt: dict[str, str] | None = None              # 票据授予票据
        self.service_ticket: dict[str, str] | None = None   # 服务票据
        
        # 会话密钥
        self.session_key_c_tgs = ""                         # C与TGS的会话密钥
        self.encrypted_session_key_c_tgs: dict[str, str] | None = None  # 加密的Kc,tgs（用于展示）
        self.session_key_c_v = ""                           # C与服务端的会话密钥
        self.encrypted_session_key_c_v: dict[str, str] | None = None    # 加密的Kc,v（用于展示）
        
        # 会话状态
        self.session_id = ""
        self.salt = ""              # 用户盐值（从AS获取）
        self.client_key = ""        # 用户派生密钥（密码+salt）
        self.chat_mutual_auth: dict[str, Any] | None = None
        self.last_authenticator_ts = 0
        self.as_client_part_plaintext: dict[str, Any] | None = None
        self.tgs_client_part_plaintext: dict[str, Any] | None = None
        self.authenticator_tgs_plaintext: dict[str, Any] | None = None
        self.authenticator_v_plaintext: dict[str, Any] | None = None
        
        # 消息游标（记录已读消息ID，防止重复拉取）
        self.last_message_ids: dict[str, int] = {}
        
        # RSA密钥对
        self.private_key_pem, self.public_key_pem = generate_key_pair()
        self.public_key_fingerprint = sha256_hex(self.public_key_pem.encode("utf-8"))

        # 在构造完成后，如果仍未设置 client_addr，尝试通过临时 UDP socket 推断本地出站 IP
        if not self.client_addr:
            try:
                import socket

                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # 不需要真正发送数据，仅用于确定本地连接地址
                # 首先尝试连接 AS 以获取出站地址
                try:
                    s.connect((self.as_host, int(self.as_port)))
                    candidate = s.getsockname()[0]
                except Exception:
                    candidate = ""

                # 如果候选地址为空或是回环地址，则尝试其它常见获取方法
                if not candidate or candidate.startswith("127.") or candidate == "0.0.0.0":
                    try:
                        candidate = socket.gethostbyname(socket.gethostname())
                    except Exception:
                        candidate = candidate or ""

                # 更进一步地尝试获取非回环地址列表
                if not candidate or candidate.startswith("127."):
                    try:
                        host_info = socket.gethostbyname_ex(socket.gethostname())
                        for ip in host_info[2]:
                            if ip and not ip.startswith("127.") and not ip.startswith("0."):
                                candidate = ip
                                break
                    except Exception:
                        pass

                self.client_addr = candidate or ""
            except Exception:
                # 回退到回环地址
                self.client_addr = ""
            finally:
                try:
                    s.close()
                except Exception:
                    pass
        
        # 离线消息缓存（认证时服务器推送的未读消息）
        self.offline_messages: list[dict] = []
        
        # 各步的请求/响应数据（用于分步显示）
        self.as_request: dict[str, Any] | None = None
        self.as_response: dict[str, Any] | None = None
        self.tgs_request: dict[str, Any] | None = None
        self.tgs_response: dict[str, Any] | None = None
        self.chat_request: dict[str, Any] | None = None
        self.chat_response: dict[str, Any] | None = None

    def reset_session(self) -> None:
        """重置会话状态，用于重新登录"""
        self.seq = 1
        self.tgt = None
        self.service_ticket = None
        self.session_key_c_tgs = ""
        self.session_key_c_v = ""
        self.session_id = ""
        self.salt = ""
        self.client_key = ""
        self.tgt_client_addr = ""
        self.service_ticket_client_addr = ""
        self.chat_mutual_auth = None
        self.last_authenticator_ts = 0
        self.as_client_part_plaintext = None
        self.tgs_client_part_plaintext = None
        self.authenticator_tgs_plaintext = None
        self.authenticator_v_plaintext = None
        self.last_message_ids = {}
        self.offline_messages = []

    def run_stage(self, stage_code: str) -> tuple[bool, str]:
        """执行一个认证阶段并返回结果
        
        参数:
            stage_code: 阶段代码（如"C_AS_REQ"）
        
        返回:
            (是否成功, 显示详情)
        """
        stage_handlers = {
            "C_AS_REQ": self._request_tgt,      # 请求TGT
            "AS_C_REP": self._explain_as_response,  # 解释AS响应
            "C_TGS_REQ": self._request_service_ticket,  # 请求服务票据
            "TGS_C_REP": self._explain_tgs_response,    # 解释TGS响应
            "C_V_REQ": self._request_chat_auth,     # 请求聊天室认证
            "V_C_REP": self._explain_chat_response, # 解释聊天室响应
        }
        try:
            return True, stage_handlers[stage_code]()
        except Exception as exc:
            return False, f"认证阶段失败：{exc}"

    def _request_tgt(self) -> str:
        """步骤1：Client请求 TGT
        公式：C -> AS: ID_C || ID_TGS || TS_1
        """
        body = {
            "id_c": self.username,          # 用户名
            "id_tgs": "tgs_server",        # 请求TGS服务
            "ts_1": self._next_seq_timestamp(),
            "extensions": {
                "client_type": self.client_type,
            },
        }
        message = Message(
            type="C_AS_REQ",               # 请求类型：客户端-》AS请求
            seq=self._next_seq(),
            body=body,
        )
        response = request(self.as_host, self.as_port, message, timeout=10.0)
        self._raise_on_error(response)
        
        # 保存请求和响应供后续使用
        self.as_request = message.to_dict()
        self.as_response = response
        
        # 解析响应
        response_body = response["body"]
        client_part = response_body["client_part"]
        extensions = self._extensions(response_body)
        self.salt = str(extensions.get("salt", ""))
        
        # 用密码派生长期密钥 Kc = SHA256(password + salt)
        self.client_key = salted_password_hash(self.password, self.salt)
        
        # 保存加密的会话密钥
        self.encrypted_session_key_c_tgs = client_part
        try:
            client_part_plaintext = self._decrypt_client_part(client_part, self.client_key)
        except Exception as exc:
            raise ValueError("密码错误，无法用本地派生的长期密钥 Kc 解密 AS 响应") from exc
        self.as_client_part_plaintext = client_part_plaintext
        
        # 解密会话密钥 Kc,tgs（用长期密钥Kc解密）
        self.session_key_c_tgs = str(client_part_plaintext.get("k_c_tgs", ""))
        if not self.session_key_c_tgs:
            raise ValueError("AS响应未返回标准字段 k_c_tgs")
        if client_part_plaintext.get("id_tgs") != "tgs_server":
            raise ValueError("AS响应中的 id_tgs 与请求不匹配")
        
        # 保存状态
        self.tgt = client_part_plaintext.get("ticket_tgs", {})
        # 保存 TGT 中的客户端地址，用于步骤3中的认证器（确保与 TGS 验证一致）
        self.tgt_client_addr = str(client_part_plaintext.get("ad_c", self.client_addr))
        self.tgs_host = str(client_part_plaintext.get("tgs_host", self.tgs_host))
        self.tgs_port = int(client_part_plaintext.get("tgs_port", self.tgs_port))
        self.session_id = str(extensions.get("session_id", ""))
        
        # 仅返回send 部分
        return json.dumps(
            {
                "公式": "C -> AS: ID_C || ID_TGS || TS_1",
                "send": self._display_protocol(self.as_request),
            },
            ensure_ascii=False,
            indent=2,
        )

    def _explain_as_response(self) -> str:
        """步骤 2 AS 返回 TGT"""
        # 从已保存的 AS 响应中提取 extensions
        as_ext = self._extensions(self.as_response.get("body", {})) if self.as_response else {}
        return json.dumps(
            {
                "公式": "AS -> C: E_Kc[K_c,tgs || ID_tgs || TS_2 || LIFETIME_2 || TICKET_tgs]",
                "receive": self._display_protocol(self.as_response),
                "plaintext": {
                    "k_c_tgs": self.session_key_c_tgs,
                    "id_tgs": self.as_client_part_plaintext.get("id_tgs"),
                    "ts_2": self.as_client_part_plaintext.get("ts_2"),
                    "lifetime_2": self.as_client_part_plaintext.get("lifetime_2"),
                    "ticket_tgs": self._display_protocol(self.as_client_part_plaintext.get("ticket_tgs")),
                    "tgs_host": self.as_client_part_plaintext.get("tgs_host"),
                    "tgs_port": self.as_client_part_plaintext.get("tgs_port"),
                },
                "extensions": as_ext,
            },
            ensure_ascii=False,
            indent=2,
        )

    def _request_service_ticket(self) -> str:
        """步骤3 Client请求 Service Ticket
        
        公式：C -> TGS: ID_V || Ticket_tgs || Authenticator_c
        """
        if not self.tgt:
            raise ValueError("缺少TGT，请先执行C_AS_REQ步骤")
        
        # 构造authenticator并用Kc,tgs加密
        # 使用 TGT 中保存的客户端地址，而非重新推断的地址，确保与 TGS 验证一致
        auth = issue_authenticator(self.username, self.tgt_client_addr or self.client_addr)
        authenticator = encrypt_model(auth, self.session_key_c_tgs)
        self.authenticator_tgs_plaintext = {
            "id_c": self.username,
            "ad_c": self.tgt_client_addr or self.client_addr,
            "ts_3": int(auth.timestamp),
        }
        self.last_authenticator_ts = int(auth.timestamp)
        
        body = {
            "id_v": "chat_server",          # 请求聊天服务
            "ticket_tgs": self.tgt,          # TGT票据
            "authenticator_c": authenticator, # 加密的认证器
        }
        message = Message(
            type="C_TGS_REQ",               # 请求类型：客户端→TGS请求
            seq=self._next_seq(),
            body=body,
        )
        response = request(self.tgs_host, self.tgs_port, message, timeout=10.0)
        self._raise_on_error(response)
        
        # 保存请求和响应供后续使用
        self.tgs_request = message.to_dict()
        self.tgs_response = response
        
        # 解析响应
        response_body = response["body"]
        client_part = response_body["client_part"]
        extensions = self._extensions(response_body)
        
        # 保存加密的会话密钥
        self.encrypted_session_key_c_v = client_part
        try:
            client_part_plaintext = self._decrypt_client_part(client_part, self.session_key_c_tgs)
        except Exception as exc:
            raise ValueError("无法用 Kc,tgs 解密 TGS 响应") from exc
        self.tgs_client_part_plaintext = client_part_plaintext
        
        # 用Kc,tgs解密新的会话密钥Kc,v
        self.session_key_c_v = str(client_part_plaintext.get("k_c_v", ""))
        if not self.session_key_c_v:
            raise ValueError("TGS响应未返回标准字段 k_c_v")
        
        # 保存服务票据和ChatServer地址
        if client_part_plaintext.get("id_v") != "chat_server":
            raise ValueError("TGS响应中的 id_v 与请求不匹配")
        self.service_ticket = client_part_plaintext.get("ticket_v", {})
        # 保存服务票据中的客户端地址，用于步骤5中的认证器（确保与 ChatServer 验证一致）
        self.service_ticket_client_addr = str(client_part_plaintext.get("ad_c", self.tgt_client_addr or self.client_addr))
        self.chat_host = str(client_part_plaintext.get("chat_host", self.chat_host))
        self.chat_port = int(client_part_plaintext.get("chat_port", self.chat_port))
        
        # 仅返回 send 部分 + authenticator 的结构说明（明文结构）
        return json.dumps(
            {
                "公式": "C -> TGS: ID_V || Ticket_tgs || Authenticator_c",
                "send": self._display_protocol(self.tgs_request),
                "authenticator_structure": self.authenticator_tgs_plaintext,
            },
            ensure_ascii=False,
            indent=2,
        )

    def _explain_tgs_response(self) -> str:
        """步骤 4 TGS 返回 Service Ticket"""
        # 工程扩展放在最后
        tgs_ext = self._extensions(self.tgs_response.get("body", {})) if self.tgs_response else {}
        return json.dumps(
            {
                "公式": "TGS -> C: E_Kc,tgs[K_c,v || ID_v || TS_4 || LIFETIME_4 || TICKET_v]",
                "receive": self._display_protocol(self.tgs_response),
                "plaintext": {
                    "k_c_v": self.session_key_c_v,
                    "id_v": self.tgs_client_part_plaintext.get("id_v"),
                    "ts_4": self.tgs_client_part_plaintext.get("ts_4"),
                    "lifetime_4": self.tgs_client_part_plaintext.get("lifetime_4"),
                    "ticket_v": self._display_protocol(self.tgs_client_part_plaintext.get("ticket_v")),
                    "chat_host": self.tgs_client_part_plaintext.get("chat_host"),
                    "chat_port": self.tgs_client_part_plaintext.get("chat_port"),
                },
                "extensions": tgs_ext,
            },
            ensure_ascii=False,
            indent=2,
        )

    def _request_chat_auth(self) -> str:
        """步骤5 Client请求服务
        
        公式：C -> V: Ticket_v || Authenticator_c
        """
        if not self.service_ticket:
            raise ValueError("缺少服务票据，请先执行C_TGS_REQ步骤")
        
        # 构造authenticator并用Kc,v加密
        # 使用服务票据中保存的客户端地址，而非重新推断的地址，确保与 ChatServer 验证一致
        auth = issue_authenticator(
            self.username,
            self.service_ticket_client_addr or self.client_addr,
            self.public_key_fingerprint,
        )
        self.last_authenticator_ts = int(auth.timestamp)
        authenticator = encrypt_authenticator(auth, self.session_key_c_v, timestamp_field="ts_5")
        self.authenticator_v_plaintext = {
            "id_c": self.username,
            "ad_c": self.service_ticket_client_addr or self.client_addr,
            "ts_5": self.last_authenticator_ts,
            "public_key_fingerprint": self.public_key_fingerprint,
        }
        
        body = {
            "ticket_v": self.service_ticket,        # 服务票据
            "authenticator_c": authenticator,      # 加密的认证器
            "extensions": {
                "session_id": self.session_id,       # 会话ID（用于AS心跳）
                "public_key_pem": self.public_key_pem,
            },
        }
        message = Message(
            type="C_V_REQ",                         # 请求类型：客户端→服务端请求
            seq=self._next_seq(),
            body=body,
        )
        response = request(self.chat_host, self.chat_port, message, timeout=10.0)
        self._raise_on_error(response)
        
        # 保存请求和响应供后续使用
        self.chat_request = message.to_dict()
        self.chat_response = response
        
        # 保存离线消息（认证期间服务器收到的消息）
        response_body = response["body"]
        client_part = response_body.get("client_part", {})
        try:
            client_part_plaintext = self._decrypt_client_part(client_part, self.session_key_c_v)
        except Exception as exc:
            raise ValueError("无法用 Kc,v 解密 V_C_REP 响应") from exc
        expected_ts = self.last_authenticator_ts + 1
        if int(client_part_plaintext.get("ts_5_plus_1", -1)) != expected_ts:
            raise ValueError("V_C_REP 的 ts_5_plus_1 校验失败")
        self.chat_mutual_auth = client_part_plaintext
        self.offline_messages = self._extensions(response_body).get("offline_messages", [])
        
        # 仅返回 send 部分 + authenticator 的结构说明，extensions 放在尾部
        chat_req_ext = self._extensions(self.chat_request.get("body", {})) if self.chat_request else {}
        return json.dumps(
            {
                "公式": "C -> V: Ticket_v || Authenticator_c",
                "send": self._display_protocol(self.chat_request),
                "authenticator_structure": self.authenticator_v_plaintext,
                "extensions": chat_req_ext,
            },
            ensure_ascii=False,
            indent=2,
        )

    def _explain_chat_response(self) -> str:
        """步骤6 Client/Server 相互认证"""
        chat_ext = self._extensions(self.chat_response.get("body", {})) if self.chat_response else {}
        return json.dumps(
            {
                "公式": "V -> C: E_Kc,v[TS_5 + 1]",
                "receive": self._display_protocol(self.chat_response),
                "plaintext": {
                    "ts_5_plus_1": self.chat_mutual_auth.get("ts_5_plus_1"),
                },
                "authenticated": True,
                "extensions": chat_ext,
            },
            ensure_ascii=False,
            indent=2,
        )

    def _next_seq(self) -> int:

        """获取下一个消息序列号（线程安全）"""
        value = self.seq
        self.seq += 1
        return value

    def send_chat_message(self, text: str, chat_type: str = "group", recipient: str = "") -> dict[str, Any]:
        """发送加密聊天消息（登录后消息）
        
        安全机制：
        1. 用会话密钥Kc,v加密消息内容（DES-CBC）
        2. 对消息体计算HMAC摘要
        3. 用RSA私钥签名
        4. 携带公钥用于服务器验证
        
        参数:
            text: 消息明文
            chat_type: "group" 或 "private"
            recipient: 私聊时的接收者用户名
        
        返回:
            发送的消息、服务器响应、解密后的ACK、消息ID
        """
        # 检查认证状态
        if not self.service_ticket or not self.session_key_c_v:
            raise ValueError("聊天会话未认证，请先完成Kerberos认证")
        
        # 1. 用会话密钥加密消息内容
        message_cipher = encrypt_text(text, self.session_key_c_v)
        
        # 2. 构建消息体
        body = {
            "ticket_v": self.service_ticket,  # 服务票据
            "message_cipher": message_cipher,       # 加密的消息
            "chat_type": chat_type,                 # 消息类型
            "recipient": recipient,                 # 接收者（私聊）
        }
        
        # 3. 生成HMAC摘要和RSA签名（登录后必须签名）
        digest, signature = sign_body(body, self.private_key_pem, self.session_key_c_v)
        
        # 4. 封装消息
        message = Message(
            type="CHAT_SEND",
            seq=self._next_seq(),
            body=body,
            hmac=digest,            # HMAC摘要
            sig=signature,          # RSA签名
        )
        
        # 5. 发送请求
        response = request(self.chat_host, self.chat_port, message, timeout=10.0)
        self._raise_on_error(response)
        
        # 6. 更新消息游标（防止重复拉取）
        message_id = int(response["body"].get("message_id", 0))
        if message_id:
            session_key = self._session_key(chat_type, recipient)
            self.last_message_ids[session_key] = max(self.last_message_ids.get(session_key, 0), message_id)
        
        # 7. 解密服务器ACK
        ack = response["body"].get("ack_cipher")
        plaintext_ack = ""
        if ack:
            plaintext_ack = decrypt_text(ack["ciphertext"], ack["iv"], self.session_key_c_v)
        
        return {
            "sent": message.to_dict(),
            "received": response,
            "ack": plaintext_ack,
            "message_id": message_id,
        }

    def send_image(
        self,
        file_path: str,
        progress_callback=None,
        chat_type: str = "group",
        recipient: str = "",
        preview_callback=None,
    ) -> dict[str, Any]:
        """发送加密图片到聊天服务器
        
        流程：
        1. 读取图片并压缩（最大1280x1280）
        2. Base64编码
        3. DES加密
        4. RSA签名
        5. 发送到服务器
        
        参数:
            file_path: 图片文件路径
            progress_callback: 进度回调函数 (进度百分比, 消息)
            chat_type: "group" 或 "private"
            recipient: 私聊接收者
            preview_callback: 预览回调函数 (文件名, base64图片)
        
        返回:
            包含成功状态、文件名、base64数据、消息ID的字典
        """
        import os
        from base64 import b64encode
        
        # 检查认证状态
        if not self.service_ticket or not self.session_key_c_v:
            raise ValueError("聊天会话未认证")
        
        # 步骤1: 读取并压缩图片
        # 所以限制在实用的显示尺寸
        if progress_callback:
            progress_callback(35, "正在压缩图片...")
        image_data, output_name, original_size = self._prepare_image_payload(file_path)
        
        # 大小限制：最大10MB
        max_size = 10 * 1024 * 1024
        if len(image_data) > max_size:
            return {"success": False, "error": "压缩后图片仍超过限制（最大10MB）"}
        
        # 步骤2: Base64编码
        if progress_callback:
            progress_callback(40, "正在编码图片...")
        image_base64 = b64encode(image_data).decode()
        
        # 可选：预览回调
        if preview_callback:
            preview_callback(output_name, image_base64)
        
        # 步骤3: DES加密
        if progress_callback:
            progress_callback(50, "正在加密数据...")
        image_cipher = encrypt_text(image_base64, self.session_key_c_v)
        
        # 步骤4: 构建消息体
        if progress_callback:
            progress_callback(60, "正在准备发送...")
        
        body = {
            "ticket_v": self.service_ticket,
            "image_cipher": image_cipher,       # 加密的图片数据
            "file_name": output_name,           # 输出文件名
            "file_size": len(image_data),       # 压缩后大小
            "original_size": original_size,     # 原始大小
            "chat_type": chat_type,
            "recipient": recipient,
        }
        
        # 步骤5: HMAC和RSA签名
        digest, signature = sign_body(body, self.private_key_pem, self.session_key_c_v)
        
        # 步骤6: 封装消息
        message = Message(
            type="IMAGE_SEND",
            seq=self._next_seq(),
            body=body,
            hmac=digest,
            sig=signature,
        )
        
        # 步骤7: 发送（超时60秒）
        if progress_callback:
            progress_callback(70, "正在上传图片...")
        response = request(self.chat_host, self.chat_port, message, timeout=60.0)
        
        if progress_callback:
            progress_callback(75, "等待服务器响应...")
        self._raise_on_error(response)
        
        # 更新消息游标
        message_id = int(response["body"].get("message_id", 0))
        if message_id:
            session_key = self._session_key(chat_type, recipient)
            self.last_message_ids[session_key] = max(self.last_message_ids.get(session_key, 0), message_id)

        # 解密ACK
        ack = response["body"].get("ack_cipher")
        plaintext_ack = ""
        if ack:
            plaintext_ack = decrypt_text(ack["ciphertext"], ack["iv"], self.session_key_c_v)

        return {
            "success": True,
            "file_name": output_name,
            "image_base64": image_base64,
            "message_id": message_id,
            "ack": plaintext_ack,
        }

    @staticmethod
    def _prepare_image_payload(file_path: str) -> tuple[bytes, str, int]:
        """准备图片数据（压缩并返回）
        
        参数:
            file_path: 图片文件路径
        
        返回:
            (压缩后的图片数据, 输出文件名, 原始文件大小)
        
        处理逻辑:
        1. 如果没有PIL库，直接返回原始数据
        2. 有PIL的话：
           - 自动旋转（根据EXIF信息）
           - 缩放到最大1280x1280
           - 透明图片保存为PNG，否则保存为JPEG（质量75）
        """
        import os
        from io import BytesIO

        # 读取原始数据
        with open(file_path, "rb") as file:
            original_data = file.read()

        # 尝试导入PIL库
        try:
            from PIL import Image, ImageOps
        except ImportError:
            return original_data, os.path.basename(file_path), len(original_data)

        # 最大尺寸限制
        max_side = 1280
        
        try:
            with Image.open(file_path) as image:
                # 自动旋转（处理手机拍摄的照片）
                image = ImageOps.exif_transpose(image)
                
                # 缩放到指定尺寸（保持比例）
                image.thumbnail((max_side, max_side), Image.Resampling.LANCZOS)
                
                # 判断是否有透明通道
                has_alpha = image.mode in ("RGBA", "LA") or (
                    image.mode == "P" and "transparency" in image.info
                )
                
                buffer = BytesIO()
                
                # 根据是否透明选择格式
                if has_alpha:
                    image.save(buffer, format="PNG", optimize=True)
                    extension = ".png"
                else:
                    # 转换为RGB（如果不是的话）
                    if image.mode != "RGB":
                        image = image.convert("RGB")
                    image.save(buffer, format="JPEG", quality=75, optimize=True, progressive=True)
                    extension = ".jpg"
                
                compressed = buffer.getvalue()
        except Exception:
            # 处理失败，返回原始数据
            return original_data, os.path.basename(file_path), len(original_data)

        base_name, _ = os.path.splitext(os.path.basename(file_path))
        return compressed, f"{base_name}_safechat{extension}", len(original_data)

    def poll_chat_messages(self, chat_type: str = "group", recipient: str = "") -> list[dict[str, Any]]:
        """拉取并解密消息（增量拉取）
        
        参数:
            chat_type: "group" 或 "private"
            recipient: 私聊接收者
        
        返回:
            已解密的消息列表（包含文本、发送者、时间戳等）
        
        流程:
        1. 发送最后已读消息ID
        2. 服务器返回新消息
        3. 用Kc,v解密每条消息
        4. 更新消息游标
        """
        if not self.service_ticket or not self.session_key_c_v:
            raise ValueError("聊天会话未认证")
        
        # 获取会话唯一标识
        session_key = self._session_key(chat_type, recipient)
        
        # 构造请求（只拉取last_seen_id之后的消息）
        body = {
            "ticket_v": self.service_ticket,
            "last_seen_id": self.last_message_ids.get(session_key, 0),  # 增量拉取
            "chat_type": chat_type,
            "recipient": recipient,
        }
        digest, signature = sign_body(body, self.private_key_pem, self.session_key_c_v)
        message = Message(
            type="CHAT_POLL",
            seq=self._next_seq(),
            body=body,
            hmac=digest,
            sig=signature,
        )
        
        response = request(self.chat_host, self.chat_port, message, timeout=30.0)
        self._raise_on_error(response)
        
        # 解密消息列表
        decrypted = []
        for item in response["body"].get("messages", []):
            cipher = item["message_cipher"]
            text = decrypt_text(cipher["ciphertext"], cipher["iv"], self.session_key_c_v)
            message_id = int(item["id"])
            
            # 更新消息游标
            self.last_message_ids[session_key] = max(self.last_message_ids.get(session_key, 0), message_id)
            
            msg_data = {
                "id": message_id,
                "sender": item["sender"],
                "recipient": item.get("recipient", ""),
                "chat_type": item.get("chat_type", "group"),
                "timestamp": item["timestamp"],
                "text": text,
                "ciphertext": str(cipher),
                "hmac": item.get("hmac", ""),
                "sig": item.get("sig", ""),
            }
            
            if item.get("has_image"):
                msg_data["has_image"] = True
                msg_data["file_name"] = item.get("file_name", "")
            elif item.get("image_data"):
                msg_data["image_data"] = item["image_data"]
                msg_data["file_name"] = item.get("file_name", "")
            
            decrypted.append(msg_data)
        
        return decrypted

    def fetch_message_image(self, message_id: int) -> dict[str, Any]:
        """按消息 ID 拉取并解密图片 Base64 数据。"""
        if not self.service_ticket or not self.session_key_c_v:
            raise ValueError("聊天会话未认证")

        body = {
            "ticket_v": self.service_ticket,
            "message_id": int(message_id),
        }
        digest, signature = sign_body(body, self.private_key_pem, self.session_key_c_v)
        message = Message(
            type="IMAGE_FETCH",
            seq=self._next_seq(),
            body=body,
            hmac=digest,
            sig=signature,
        )
        response = request(self.chat_host, self.chat_port, message, timeout=60.0)
        self._raise_on_error(response)
        image_cipher = response["body"]["image_cipher"]
        return {
            "message_id": int(response["body"].get("message_id", message_id)),
            "image_data": decrypt_text(image_cipher["ciphertext"], image_cipher["iv"], self.session_key_c_v),
            "file_name": response["body"].get("file_name", ""),
        }

    def reset_session_cursor(self, chat_type: str = "group", recipient: str = "") -> None:
        """重置会话游标（用于切换视图时重新加载消息）"""
        self.last_message_ids[self._session_key(chat_type, recipient)] = 0

    def _session_key(self, chat_type: str = "group", recipient: str = "") -> str:
        """生成会话唯一标识
        
        私聊：按字母顺序排列两个用户名，确保A-B和B-A是同一个会话
        群聊：固定为 group:public
        """
        if chat_type == "private":
            users = sorted([self.username, recipient])
            return f"private:{users[0]}:{users[1]}"
        return "group:public"

    def get_offline_messages(self) -> list[dict[str, Any]]:
        """获取并解密离线消息（认证阶段收到的消息）
        
        返回:
            已解密的离线消息列表
        
        注意: 获取后会清空缓存
        """
        decrypted = []
        for msg in self.offline_messages:
            text = decrypt_text(msg["message_cipher"], msg["iv"], self.session_key_c_v)
            decrypted.append({
                "id": msg["id"],
                "sender": msg["sender"],
                "recipient": self.username,
                "chat_type": msg["chat_type"],
                "timestamp": msg["created_at"],
                "text": text,
                "ciphertext": msg["message_cipher"],
            })
        
        # 获取后清空缓存（避免重复处理）
        self.offline_messages = []
        return decrypted

    def fetch_online_users(self) -> list[dict[str, Any]]:
        """获取在线用户列表"""
        if not self.service_ticket or not self.session_key_c_v:
            raise ValueError("聊天会话未认证")
        
        body = {
            "ticket_v": self.service_ticket,
        }
        digest, signature = sign_body(body, self.private_key_pem, self.session_key_c_v)
        message = Message(
            type="USER_LIST",
            seq=self._next_seq(),
            body=body,
            hmac=digest,
            sig=signature,
        )
        response = request(self.chat_host, self.chat_port, message, timeout=5.0)
        self._raise_on_error(response)
        return response["body"].get("users", [])

    def heartbeat_as_session(self) -> None:
        """AS会话心跳（保持会话活跃）
        
        定期向AS发送心跳，确保重复登录检测准确
        """
        if not self.session_id:
            return
        
        message = Message(
            type="AS_SESSION_HEARTBEAT",
            seq=self._next_seq(),
            body={
                "username": self.username,
                "extensions": {
                    "session_id": self.session_id,
                },
            },
        )
        response = request(self.as_host, self.as_port, message, timeout=3.0)
        self._raise_on_error(response)

    def admin_mute_user(self, target_username: str, duration_seconds: int = 600, reason: str = "admin mute") -> dict[str, Any]:
        """管理员禁言用户
        
        参数:
            target_username: 目标用户名
            duration_seconds: 禁言时长（默认600秒=10分钟）
            reason: 禁言原因
        
        返回:
            服务器响应
        
        注意: 需要管理员权限，由服务器验证
        """
        return self._send_admin_action(
            "ADMIN_MUTE_USER",
            {
                "target_username": target_username,
                "duration_seconds": duration_seconds,
                "reason": reason,
            },
        )

    def admin_unmute_user(self, target_username: str) -> dict[str, Any]:
        """管理员取消禁言"""
        return self._send_admin_action(
            "ADMIN_UNMUTE_USER",
            {
                "target_username": target_username,
            },
        )

    def admin_kick_user(self, target_username: str) -> dict[str, Any]:
        """管理员踢用户下线"""
        return self._send_admin_action(
            "ADMIN_KICK_USER",
            {
                "target_username": target_username,
            },
        )

    def request_admin_token(self) -> str:
        """请求管理员令牌（使用TGT，无需重新输入密码）
        
        流程:
        1. 用Kc,tgs加密authenticator
        2. 发送TGT和authenticator到AS
        3. AS验证后返回管理员令牌
        
        返回:
            管理员令牌字符串
        """
        if not self.tgt or not self.session_key_c_tgs:
            raise ValueError("缺少TGT，请先完成Kerberos认证")
        
        authenticator = encrypt_model(
            issue_authenticator(self.username, self.tgt_client_addr or self.client_addr),
            self.session_key_c_tgs,
        )
        
        message = Message(
            type="AS_ADMIN_TOKEN_REQ",
            seq=self._next_seq(),
            body={
                "ticket_tgs": self.tgt,
                "authenticator_c": authenticator,
            },
        )
        response = request(self.as_host, self.as_port, message, timeout=10.0)
        self._raise_on_error(response)
        
        token = response["body"].get("admin_token", "")
        if not token:
            raise RuntimeError("AS未返回管理员令牌")
        
        return token

    def chat_admin_list_messages(self, chat_type: str = "All", user_filter: str = "", limit: int = 200) -> list[dict[str, Any]]:
        """管理员查询消息记录
        
        参数:
            chat_type: 消息类型筛选（"All"、"group"、"private"）
            user_filter: 用户名筛选
            limit: 返回数量限制
        
        返回:
            消息列表
        """
        body = self._send_admin_action(
            "CHAT_ADMIN_LIST_MESSAGES",
            {
                "chat_type": chat_type,
                "user_filter": user_filter,
                "limit": limit,
            },
        )
        return body.get("messages", [])

    def chat_admin_audit_query(self, action_filter: str = "", limit: int = 300) -> list[dict[str, Any]]:
        """管理员查询审计日志
        
        参数:
            action_filter: 操作类型筛选
            limit: 返回数量限制
        
        返回:
            审计日志列表
        """
        body = self._send_admin_action(
            "CHAT_ADMIN_AUDIT_QUERY",
            {
                "action_filter": action_filter,
                "limit": limit,
            },
        )
        return body.get("audit_logs", [])

    def chat_admin_set_role(self, target_username: str, role: str) -> dict[str, Any]:
        """管理员设置用户角色"""
        return self._send_admin_action(
            "CHAT_ADMIN_SET_ROLE",
            {
                "target_username": target_username,
                "role": role,
            },
        )

    def chat_admin_delete_user(self, target_username: str) -> dict[str, Any]:
        """管理员删除用户（ChatServer本地）"""
        return self._send_admin_action(
            "CHAT_ADMIN_DELETE_USER",
            {
                "target_username": target_username,
            },
        )

    def _send_admin_action(self, action_type: str, body_fields: dict[str, Any]) -> dict[str, Any]:
        """发送管理员操作请求（内部方法）
        
        参数:
            action_type: 操作类型
            body_fields: 操作参数
        
        返回:
            服务器响应体
        """
        if not self.service_ticket or not self.session_key_c_v:
            raise ValueError("聊天会话未认证")
        
        body = {
            "ticket_v": self.service_ticket,
            **body_fields,
        }
        
        # 生成签名
        digest, signature = sign_body(body, self.private_key_pem, self.session_key_c_v)
        
        message = Message(
            type=action_type,
            seq=self._next_seq(),
            body=body,
            hmac=digest,
            sig=signature,
        )
        
        response = request(self.chat_host, self.chat_port, message, timeout=10.0)
        self._raise_on_error(response)
        return response["body"]

    @staticmethod
    def _raise_on_error(response: dict[str, Any]) -> None:
        """检查响应是否为错误，是则抛出异常"""
        if response["type"] == "ERROR":
            raise RuntimeError(response["body"].get("error", "未知服务器错误"))

    @staticmethod
    def _extensions(body: dict[str, Any]) -> dict[str, Any]:
        extensions = body.get("extensions", {})
        return extensions if isinstance(extensions, dict) else {}

    @staticmethod
    def _decrypt_client_part(client_part: dict[str, str], secret: str) -> dict[str, Any]:
        plaintext = decrypt_text(client_part["ciphertext"], client_part["iv"], secret)
        return json.loads(plaintext)

    @staticmethod
    def _next_seq_timestamp() -> int:
        return int(time.time() * 1000)

    @staticmethod
    def _format_exchange(sent: dict[str, Any], received: dict[str, Any]) -> str:
        """格式化请求/响应为JSON字符串"""
        return json.dumps(
            {"send": AuthClient._display_protocol(sent), "receive": AuthClient._display_protocol(received)},
            ensure_ascii=False,
            indent=2,
        )

    @staticmethod
    def _format_state(state: dict[str, Any]) -> str:
        """格式化状态为JSON字符串（用于UI展示）"""
        return json.dumps(AuthClient._display_protocol(state), ensure_ascii=False, indent=2)

    @staticmethod
    def _display_protocol(value: Any) -> Any:
        if isinstance(value, dict):
            if set(value.keys()) == {"ciphertext", "iv"}:
                return value["ciphertext"]
            out: dict[str, Any] = {}
            for key, item in value.items():
                disp = AuthClient._display_protocol(item)
                # 移除空字符串或空容器字段，便于界面展示。
                if disp == "" or disp is None:
                    continue
                if isinstance(disp, dict) and not disp:
                    continue
                if isinstance(disp, list) and not disp:
                    continue
                out[key] = disp
            return out
        if isinstance(value, list):
            return [AuthClient._display_protocol(item) for item in value]
        return value
