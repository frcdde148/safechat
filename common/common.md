# common 模块讲解

`common/` 是整个 SafeChat 项目的**公共基础库**，所有服务端（AS/TGS/Chat）和客户端都只从这里引用密码学、数据模型和协议工具，不重复实现。

---

## 目录结构速览

```
common/
├── config/
│   ├── settings.json   ← 唯一的运行时配置文件（IP、端口、密钥）
│   └── settings.py     ← 读取配置的工具函数
├── crypto/             ← 三大算法，全部纯 Python 手写
│   ├── sha256.py       ← SHA-256 + HMAC-SHA256
│   ├── des.py          ← DES-CBC 加密/解密
│   └── rsa_sign.py     ← RSA-1024 签名/验证
├── models/
│   └── tickets.py      ← Kerberos 票据 & 认证子数据结构
└── protocol/
    ├── actions.py      ← 消息类型枚举 & 安全等级
    ├── message.py      ← 统一协议封装（Message 类）
    ├── security.py     ← 消息摘要 & 签名验证
    ├── socket_io.py    ← TCP 收发（4字节长度前缀帧）
    └── admin_token.py  ← 管理员令牌签发/验证
```

---

## 一、config/ — 配置

### settings.json

运行时唯一需要修改的文件：

| 字段 | 含义 |
|---|---|
| `as_server.public_host` | AS 服务器对外 IP，客户端登录时连这个地址 |
| `tgs_server.public_host` | TGS 服务器对外 IP |
| `chat_server.public_host` | Chat 服务器对外 IP |
| `*.service_key` | 服务器之间共享的 DES 加密密钥（加密票据用） |
| `database.*_path` | 各服务器 SQLite 数据库文件路径 |
| `security.admin_token_secret` | 管理员令牌的 HMAC 签名密钥 |

### settings.py — 主要函数

```python
load_settings()               # 读取 settings.json，缺失字段用默认值补全
database_path(role)           # role="as"/"tgs"/"chat" → 返回对应数据库的 Path
server_bind_address(section)  # 返回 (bind_host, port)，服务器监听用
service_address(section)      # 返回 (public_host, port)，注册到数据库用
service_key(section)          # 返回该服务的共享密钥字符串
```

---

## 二、crypto/ — 密码学算法

> **重点**：三个算法均为**纯 Python 从零实现**，没有调用 cryptography、pycryptodome 等第三方库。

### 2.1 sha256.py — SHA-256 & HMAC

**SHA-256 原理（FIPS 180-4）**

1. **消息填充**：原始消息末尾加 `0x80`，再补零，最后附加 64 位的原始消息长度，使总长度为 512 位的整数倍。
2. **分块压缩**：每 512 位一块，运行 64 轮压缩函数，每轮用右旋（ROTR）、异或、与/非等位运算更新 8 个 32 位工作变量 `a~h`。
3. **输出**：8 个 32 位哈希值拼接 = 256 位摘要。

```python
sha256_bytes(data) -> bytes                            # 原始字节输出
sha256_hex(data) -> str                                # 十六进制字符串输出
salted_password_hash(password, salt_hex) -> str        # SHA256(salt + password)
verify_password(password, salt_hex, expected) -> bool  # 安全比较（防时序攻击）
hmac_sha256(key, message) -> bytes                     # HMAC-SHA256
hmac_compare_digest(a, b) -> bool                      # 常数时间比较（防时序攻击）
```

**HMAC 结构（RFC 2104）**：
```
HMAC(K, M) = H( (K' XOR opad) || H( (K' XOR ipad) || M ) )
```

**在项目中的用途**：
- 密码存储：`salted_password_hash` 结果存入 AS 数据库
- 消息完整性：CHAT_SEND 的 `hmac` 字段 = `sha256_hex(canonical_body)`
- 管理员令牌：`hmac_sha256` 对令牌载荷签名

---

### 2.2 des.py — DES-CBC 加密

**DES 原理（FIPS 46-3）**

| 步骤 | 说明 |
|---|---|
| 密钥派生 | `SHA256(secret)` 取前 8 字节 → 64 位 DES 密钥 |
| 初始置换 IP | 64 位明文按 IP 表重排位顺序 |
| 16 轮 Feistel | 右半部分经扩展置换 E（32→48位）→ 与 48 位轮密钥 XOR → 经 8 个 S 盒压缩回 32 位 → P 置换 → 与左半异或 |
| 末置换 FP | IP 的逆置换，输出 64 位密文 |
| CBC 模式 | 每块明文先与上一块密文 XOR 再加密，首块用随机 8 字节 IV |
| PKCS#7 填充 | 不足 8 字节时末尾补 n 个值为 n 的字节 |

```python
encrypt_text(plaintext, secret) -> {"ciphertext": "base64...", "iv": "base64..."}
decrypt_text(ciphertext_b64, iv_b64, secret) -> str
```

**在项目中的用途**：
- TGT 用 TGS 服务密钥加密；服务票据用 Chat 服务密钥加密
- CHAT_SEND 的 `message_cipher` 用 `session_key_c_v` 加密
- 审计日志内容用 AS 自身密钥加密

---

### 2.3 rsa_sign.py — RSA-1024 签名

**RSA 流程**

| 步骤 | 说明 | 核心代码 |
|---|---|---|
| 密钥生成 | 随机生成两个 512 位质数 p、q，Miller-Rabin 测试验证 | `_gen_prime()` |
| 计算参数 | n=p×q，φ=(p-1)(q-1)，e=65537，d=e⁻¹ mod φ | `_generate_rsa_key()` |
| PEM 编码 | 私钥 PKCS#1，公钥 SubjectPublicKeyInfo，手工拼 ASN.1/DER | `_*_to_pem()` |
| 签名 | `sig = PKCS1_v1.5_pad(SHA256(msg))^d mod n`，CRT 加速 | `sign_text()` |
| 验证 | `em = sig^e mod n`，检查填充和摘要是否吻合 | `verify_text()` |

**PKCS#1 v1.5 签名块**：
```
0x00 | 0x01 | 0xFF...FF | 0x00 | DigestInfo(SHA256摘要)
```

```python
generate_key_pair(bits=1024) -> (private_pem, public_pem)  # 客户端登录时生成
sign_text(text, private_key_pem) -> str                    # Base64 签名
verify_text(text, signature_b64, public_key_pem) -> bool   # 验证签名
```

**在项目中的用途**：
- 客户端每条 CHAT_SEND / IMAGE_SEND / 管理员操作都用 RSA 私钥签名
- Chat Server 从数据库取出公钥验证，保证不可否认性

---

## 三、models/tickets.py — 票据模型

### Ticket（票据）

```python
@dataclass
class Ticket:
    client_id: str      # 用户名
    client_addr: str    # 客户端 IP（防票据盗用）
    session_key: str    # 会话密钥（16字节随机 hex）
    service_id: str     # 目标服务（"tgs_server" / "chat_server"）
    issued_at: int      # 签发时间（毫秒时间戳）
    expires_at: int     # 过期时间（签发 + 30分钟）
```

- **TGT**：service_id="tgs_server"，用 TGS 服务密钥加密后发给客户端
- **服务票据**：service_id="chat_server"，用 Chat 服务密钥加密后发给客户端

### Authenticator（认证子）

```python
@dataclass
class Authenticator:
    client_id: str   # 用户名
    client_addr: str # 客户端 IP
    timestamp: int   # 当前时间戳（毫秒，防重放）
```

认证子用**会话密钥**加密，服务器解密后核对 `client_id` 和 `client_addr` 是否与票据吻合。

### 关键函数

```python
issue_ticket(client_id, client_addr, session_key, service_id) -> Ticket
issue_authenticator(client_id, client_addr) -> Authenticator
encrypt_model(model, secret) -> {"ciphertext": ..., "iv": ...}  # DES 加密
decrypt_ticket(encrypted_dict, secret) -> Ticket
decrypt_authenticator(encrypted_dict, secret) -> Authenticator
```

---

## 四、protocol/ — 协议层

### 4.1 actions.py — 消息类型

| 层级 | 消息类型示例 | 安全机制 |
|---|---|---|
| control | HEARTBEAT, ERROR | 无 |
| auth | C_AS_REQ / AS_C_REP / C_TGS_REQ / TGS_C_REP / C_V_REQ / V_C_REP | 票据加密 |
| data | CHAT_SEND / IMAGE_SEND / ADMIN_* | DES加密 + SHA256摘要 + RSA签名 |

`SIGNED_TYPES` 集合定义哪些消息**必须携带 RSA 签名**。

### 4.2 message.py — 消息封装

每条 TCP 消息的统一格式：

```python
@dataclass
class Message:
    type: str    # 消息类型（必须在 ALL_TYPES 中，否则 validate_message 抛异常）
    seq: int     # 序列号（单调递增，防重放）
    body: dict   # 业务数据
    sid: str     # 会话 ID
    v: int       # 协议版本（固定为 1）
    ts: int      # 发送时间戳（毫秒）
    nonce: str   # 8字节随机数（防重放）
    hmac: str    # 消息体 SHA-256 摘要
    sig: str     # RSA 签名（Base64）
    pubkey: str  # 发送方 RSA 公钥 PEM
```

### 4.3 security.py — 摘要 & 签名

```python
body_digest(body) -> str                                        # SHA-256 摘要（sort_keys 确定性序列化）
sign_body(body, private_key_pem) -> (digest, signature)        # 一步签名
verify_body_signature(body, digest, sig, public_key_pem) -> bool  # 两步验证
```

**验证流程**：
1. 重算 `body_digest(body)` 与传入 digest 比对 → 防篡改
2. RSA 验证 `verify_text(digest, sig, pubkey)` → 防伪造/不可否认

### 4.4 socket_io.py — TCP 传输

帧格式：`[4字节大端无符号整数：消息长度][JSON字节]`

```python
send_message(sock, message)           # 序列化 + 发送
recv_message(sock) -> dict            # 接收 + 解析
request(host, port, message) -> dict  # 短连接（默认5秒超时）
```

### 4.5 admin_token.py — 管理员令牌

格式：`base64url(payload).base64url(HMAC-SHA256(secret, payload))`

```python
issue_admin_token(username, lifetime_seconds=3600) -> str  # 签发，默认1小时
verify_admin_token(token) -> dict | None                   # 验签 + 检查过期
```

管理员登录 AS 后获得此令牌，跨服务调用管理 API 时携带在 `body.admin_token`。

---

## 五、常见问题速查

**Q：DES 密钥是 8 字节，为什么 secret 可以是任意长字符串？**  
`derive_des_key(secret)` 先 SHA-256，取前 8 字节，任意长度的密钥都能映射到固定 8 字节。

**Q：为什么密码存储不直接 SHA-256(password)？**  
使用 `SHA256(salt + password)`，salt 是每个用户独立的 32 字节随机值，防彩虹表攻击——即使两用户密码相同，哈希值也不同。

**Q：消息的 `hmac` 字段到底是 HMAC 还是普通摘要？**  
是**普通 SHA-256 摘要**（`body_digest`），字段名叫 `hmac` 是历史命名，真正的完整性/认证由 RSA 签名（`sig` 字段）保证。

**Q：Ticket 里 `client_addr` 有什么用？**  
防票据盗用。服务器解票后检查 `authenticator.client_addr == ticket.client_addr`，IP 不符则拒绝。

**Q：`session_key` 是怎么产生的？谁知道它？**  
AS 用 `secrets.token_hex(16)` 随机生成，然后：① 用用户密码派生密钥加密发给客户端；② 藏在 TGT 里发给 TGS。TGS 再生成新的 `session_key_c_v` 同理分发。中间人只能看到密文，无法获得明文会话密钥。

**Q：RSA 签名和 SHA-256 摘要各防什么？**

| 机制 | 防护 |
|---|---|
| SHA-256 摘要（`hmac` 字段） | 消息体在传输中被篡改 |
| RSA 签名（`sig` 字段） | 消息伪造、抵赖——只有持有私钥的客户端才能生成有效签名 |