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
from typing import Any

# 导入加密模块
from common.crypto.des import decrypt_text, encrypt_text
from common.crypto.rsa_sign import generate_key_pair
from common.crypto.sha256 import salted_password_hash
from common.models.tickets import encrypt_model, issue_authenticator
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
        
        # 消息游标（记录已读消息ID，防止重复拉取）
        self.last_message_ids: dict[str, int] = {}
        
        # RSA密钥对（登录后签名用）
        self.private_key_pem, self.public_key_pem = generate_key_pair()
        
        # 离线消息缓存（认证时服务器推送的未读消息）
        self.offline_messages: list[dict] = []

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
        """步骤1：向AS请求TGT（票据授予票据）
        
        流程：
        1. 构造请求体（用户名、TGS标识）
        2. 发送到AS服务器
        3. 从响应中提取：加密的会话密钥、TGT、salt、TGS地址
        4. 用密码+salt派生长期密钥Kc
        5. 用Kc解密会话密钥Kc,tgs
        """
        body = {
            "username": self.username,      # 用户名
            "tgs_id": "tgs_server",        # 请求TGS服务
            "client_type": self.client_type,
        }
        message = Message(
            type="C_AS_REQ",               # 请求类型：客户端→AS请求
            seq=self._next_seq(),
            body=body,
        )
        response = request(self.as_host, self.as_port, message)
        self._raise_on_error(response)
        
        # 解析响应
        encrypted_session_key = response["body"].get("client_part", response["body"]["encrypted_session_key"])
        encrypted_tgt = response["body"]["ticket_tgt"]
        self.salt = response["body"]["salt"]
        
        # 用密码派生长期密钥 Kc = SHA256(password + salt)
        self.client_key = salted_password_hash(self.password, self.salt)
        
        # 保存加密的会话密钥（用于UI展示）
        self.encrypted_session_key_c_tgs = encrypted_session_key
        
        # 解密会话密钥 Kc,tgs（用长期密钥Kc解密）
        try:
            self.session_key_c_tgs = decrypt_text(
                encrypted_session_key["ciphertext"],
                encrypted_session_key["iv"],
                self.client_key,
            )
        except Exception as exc:
            raise ValueError("密码错误，无法用本地派生的长期密钥 Kc 解密 AS 响应") from exc
        
        # 保存状态
        self.tgt = encrypted_tgt
        self.tgs_host = response["body"]["tgs_host"]
        self.tgs_port = int(response["body"]["tgs_port"])
        self.session_id = response["body"].get("session_id", "")
        
        return self._format_exchange(message.to_dict(), response)

    def _explain_as_response(self) -> str:
        """步骤2：解释AS响应 - 展示客户端保存的信息"""
        return self._format_state(
            {
                "client_saved": {
                    "encrypted_session_key": self.encrypted_session_key_c_tgs,  # 加密的Kc,tgs
                    "salt": self.salt,                       # 用户盐值
                    "ticket_tgt": self.tgt,                  # TGT票据
                    "tgs_server": f"{self.tgs_host}:{self.tgs_port}",  # TGS地址
                }
            }
        )

    def _request_service_ticket(self) -> str:
        """步骤3：向TGS请求服务票据
        
        流程：
        1. 用Kc,tgs加密authenticator（包含用户名）
        2. 发送TGT和authenticator到TGS
        3. TGS验证TGT和authenticator
        4. 返回服务票据和新的会话密钥Kc,v
        """
        if not self.tgt:
            raise ValueError("缺少TGT，请先执行C_AS_REQ步骤")
        
        # 构造authenticator并用Kc,tgs加密
        authenticator = encrypt_model(issue_authenticator(self.username, ""), self.session_key_c_tgs)
        
        body = {
            "service_id": "chat_server",    # 请求聊天服务
            "ticket_tgt": self.tgt,         # TGT票据
            "authenticator": authenticator, # 加密的认证器
        }
        message = Message(
            type="C_TGS_REQ",               # 请求类型：客户端→TGS请求
            seq=self._next_seq(),
            body=body,
        )
        response = request(self.tgs_host, self.tgs_port, message)
        self._raise_on_error(response)
        
        # 解析响应
        encrypted_session_key = response["body"]["encrypted_session_key"]
        
        # 保存加密的会话密钥（用于UI展示）
        self.encrypted_session_key_c_v = encrypted_session_key
        
        # 用Kc,tgs解密新的会话密钥Kc,v
        self.session_key_c_v = decrypt_text(
            encrypted_session_key["ciphertext"],
            encrypted_session_key["iv"],
            self.session_key_c_tgs
        )
        
        # 保存服务票据和ChatServer地址
        self.service_ticket = response["body"]["service_ticket"]
        self.chat_host = response["body"].get("chat_host", self.chat_host)
        self.chat_port = response["body"].get("chat_port", self.chat_port)
        
        return self._format_exchange(message.to_dict(), response)

    def _explain_tgs_response(self) -> str:
        """步骤4：解释TGS响应 - 展示客户端保存的信息"""
        return self._format_state(
            {
                "client_saved": {
                    "encrypted_session_key": self.encrypted_session_key_c_v,  # 加密的Kc,v
                    "service_ticket": self.service_ticket,                    # 服务票据
                    "chat_server": f"{self.chat_host}:{self.chat_port}",      # ChatServer地址
                }
            }
        )

    def _request_chat_auth(self) -> str:
        """步骤5：向ChatServer请求认证
        
        流程：
        1. 用Kc,v加密authenticator
        2. 发送服务票据和authenticator到ChatServer
        3. 服务器验证票据和authenticator
        4. 返回双向认证信息和离线消息
        """
        if not self.service_ticket:
            raise ValueError("缺少服务票据，请先执行C_TGS_REQ步骤")
        
        # 构造authenticator并用Kc,v加密
        authenticator = encrypt_model(issue_authenticator(self.username, ""), self.session_key_c_v)
        
        body = {
            "service_ticket": self.service_ticket,  # 服务票据
            "authenticator": authenticator,        # 加密的认证器
            "session_id": self.session_id,          # 会话ID（用于AS心跳）
        }
        message = Message(
            type="C_V_REQ",                         # 请求类型：客户端→服务端请求
            seq=self._next_seq(),
            body=body,
        )
        response = request(self.chat_host, self.chat_port, message)
        self._raise_on_error(response)
        
        # 保存离线消息（认证期间服务器收到的消息）
        self.offline_messages = response["body"].get("offline_messages", [])
        
        return self._format_exchange(message.to_dict(), response)

    def _explain_chat_response(self) -> str:
        """步骤6：解释ChatServer响应 - 双向认证完成"""
        return self._format_state(
            {
                "authenticated": True,
                "room": "public",
                "message_security": "后续聊天消息使用 Kc,v 加密传输",
            }
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
            "service_ticket": self.service_ticket,  # 服务票据
            "message_cipher": message_cipher,       # 加密的消息
            "chat_type": chat_type,                 # 消息类型
            "recipient": recipient,                 # 接收者（私聊）
        }
        
        # 3. 生成HMAC摘要和RSA签名（登录后必须签名）
        digest, signature = sign_body(body, self.private_key_pem)
        
        # 4. 封装消息
        message = Message(
            type="CHAT_SEND",
            seq=self._next_seq(),
            body=body,
            hmac=digest,            # HMAC摘要
            sig=signature,          # RSA签名
            pubkey=self.public_key_pem,  # 公钥（服务器用于验证签名）
        )
        
        # 5. 发送请求
        response = request(self.chat_host, self.chat_port, message)
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
        
        # 步骤1: 读取并压缩图片（大图片经过Base64+JSON+DES后会很慢）
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
            "service_ticket": self.service_ticket,
            "image_cipher": image_cipher,       # 加密的图片数据
            "file_name": output_name,           # 输出文件名
            "file_size": len(image_data),       # 压缩后大小
            "original_size": original_size,     # 原始大小
            "chat_type": chat_type,
            "recipient": recipient,
        }
        
        # 步骤5: HMAC和RSA签名
        digest, signature = sign_body(body, self.private_key_pem)
        
        # 步骤6: 封装消息
        message = Message(
            type="IMAGE_SEND",
            seq=self._next_seq(),
            body=body,
            hmac=digest,
            sig=signature,
            pubkey=self.public_key_pem,
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
        message = Message(
            type="CHAT_POLL",
            seq=self._next_seq(),
            body={
                "service_ticket": self.service_ticket,
                "last_seen_id": self.last_message_ids.get(session_key, 0),  # 增量拉取
                "chat_type": chat_type,
                "recipient": recipient,
            },
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
            }
            
            # 如果是图片消息，包含图片数据
            if item.get("image_data"):
                msg_data["image_data"] = item["image_data"]
                msg_data["file_name"] = item.get("file_name", "")
            
            decrypted.append(msg_data)
        
        return decrypted

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
        
        message = Message(
            type="USER_LIST",
            seq=self._next_seq(),
            body={
                "service_ticket": self.service_ticket,
            },
        )
        response = request(self.chat_host, self.chat_port, message)
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
                "session_id": self.session_id,
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
        
        authenticator = encrypt_model(issue_authenticator(self.username, ""), self.session_key_c_tgs)
        
        message = Message(
            type="AS_ADMIN_TOKEN_REQ",
            seq=self._next_seq(),
            body={
                "ticket_tgt": self.tgt,
                "authenticator": authenticator,
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
            "service_ticket": self.service_ticket,
            **body_fields,
        }
        
        # 生成签名
        digest, signature = sign_body(body, self.private_key_pem)
        
        message = Message(
            type=action_type,
            seq=self._next_seq(),
            body=body,
            hmac=digest,
            sig=signature,
            pubkey=self.public_key_pem,
        )
        
        response = request(self.chat_host, self.chat_port, message)
        self._raise_on_error(response)
        return response["body"]

    @staticmethod
    def _raise_on_error(response: dict[str, Any]) -> None:
        """检查响应是否为错误，是则抛出异常"""
        if response["type"] == "ERROR":
            raise RuntimeError(response["body"].get("error", "未知服务器错误"))

    @staticmethod
    def _format_exchange(sent: dict[str, Any], received: dict[str, Any]) -> str:
        """格式化请求/响应为JSON字符串（用于UI展示）"""
        return json.dumps({"send": sent, "receive": received}, ensure_ascii=False, indent=2)

    @staticmethod
    def _format_state(state: dict[str, Any]) -> str:
        """格式化状态为JSON字符串（用于UI展示）"""
        return json.dumps(state, ensure_ascii=False, indent=2)
