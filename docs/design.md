# SafeChat 系统设计文档

## 1. 项目定位

SafeChat 是一个基于 Kerberos V4 流程并扩展数字签名与摘要校验机制的局域网认证聊天室系统。系统以聊天室作为业务服务场景，通过 `Client`、`AS`、`TGS`、`ChatServer` 四类实体展示认证、票据授权、双向认证、会话密钥分发、加密聊天和安全审计。

本项目面向网络安全课程设计和答辩演示，重点是协议流程清晰、局域网多机可运行、认证数据可展示、关键安全行为可追溯。

## 2. 总体架构

系统采用客户端层、服务层、数据层的三层架构：

```text
Client Layer  ->  Service Layer  ->  Data Layer
PyQt5 GUI         AS/TGS/Chat       SQLite/DAO/Audit
```

- 客户端层负责用户交互、认证流程编排、票据保存、消息加解密和签名处理。
- 服务层拆分为 AS、TGS、ChatServer，实现认证与业务分离。
- 数据层负责用户、服务密钥、审计日志和 IP 封禁信息的持久化。

推荐 4 机分布式部署：

| 主机 | 运行程序 | 说明 |
|---|---|---|
| Host-A | `server/as_server/main.py` | AS 认证服务器 |
| Host-B | `server/tgs_server/main.py` | TGS 票据授予服务器 |
| Host-C | `server/chat_server/main.py` | ChatServer 聊天服务器 |
| Host-D | `client/main.py` | 客户端，可扩展多台 |

## 3. 项目目录

```text
safechat/
├─ client/
│  ├─ ui/
│  ├─ controller/
│  ├─ net/
│  ├─ security/
│  └─ main.py
├─ server/
│  ├─ as_server/
│  │  ├─ core/
│  │  └─ main.py
│  ├─ tgs_server/
│  │  ├─ core/
│  │  └─ main.py
│  └─ chat_server/
│     ├─ core/
│     ├─ session/
│     ├─ routing/
│     └─ main.py
├─ common/
│  ├─ protocol/
│  ├─ crypto/
│  ├─ utils/
│  ├─ config/
│  └─ models/
├─ database/
│  ├─ init_db.py
│  ├─ dao/
│  └─ chatroom.db
├─ logs/
├─ tests/
├─ docs/
├─ scripts/
├─ requirements.txt
├─ README.md
└─ .gitignore
```

## 4. Kerberos 认证流程

系统保留 Kerberos V4 的核心票据机制：

1. `Client -> AS`：客户端提交用户标识，请求 `TGT`。
2. `AS -> Client`：AS 验证用户，返回 `Kc,tgs` 和由 `Ktgs` 加密的 `TGT`。
3. `Client -> TGS`：客户端提交 `TGT` 和 `Authenticator`，请求 ChatServer 服务票据。
4. `TGS -> Client`：TGS 返回 `Kc,v` 和由 `Kv` 加密的 `Service Ticket`。
5. `Client -> ChatServer`：客户端提交 `Service Ticket` 和 `Authenticator`。
6. `ChatServer -> Client`：服务端返回 `E(Kc,v, timestamp + 1)` 完成双向认证。

认证通过后，客户端进入公共聊天室，聊天消息使用 `Kc,v` 进行加密传输。

## 5. 扩展安全机制

系统表述为“基于 Kerberos V4 流程并扩展数字签名与摘要校验机制”，原因是 RSA 签名和 SHA-256 摘要不属于标准 Kerberos V4 的对称密钥模型。

| 机制 | 用途 |
|---|---|
| DES | 票据、认证器、会话消息的对称加密 |
| RSA-1024 | 关键操作数字签名与验签，支撑不可否认性 |
| SHA-256 | 用户密码加盐哈希、摘要校验 |
| AES | 审计日志操作内容加密存储 |
| 时间戳 + 缓存 | 票据生命周期校验和重放攻击检测 |
| IP 封禁 | 非法访问、暴力尝试后的访问控制 |

所有关键操作均应携带 RSA 签名，包括：

- `CHAT_SEND`
- `CHAT_RECV`
- `CHAT_ACK`
- `FILE_SEND`
- `FILE_RECV`
- `FILE_ACK`

## 6. 通信协议

系统采用 TCP Socket 可靠传输，应用层使用 JSON 报文。密文、签名、摘要等二进制数据统一使用 Base64 放入 JSON 字段。

每条 TCP 消息使用长度前缀封包：

```text
4 字节消息长度 + JSON 消息体
```

通用报文结构：

```json
{
  "msg_type": "CHAT_SEND",
  "version": "safechat-kerberos-v4-ext",
  "request_id": "uuid-string",
  "timestamp": 1710000000000,
  "payload": {},
  "digest": "sha256-hex",
  "signature": "base64-rsa-signature"
}
```

## 7. 数据库设计

### users 用户信息表

| 字段名 | 类型 | 约束 | 说明 |
|---|---|---|---|
| `id` | INTEGER | PK, AUTO | 用户唯一 ID |
| `username` | TEXT | UNIQUE, NOT NULL | 用户名 |
| `password_hash` | TEXT | NOT NULL | SHA-256 加盐哈希值 |
| `salt` | TEXT | NOT NULL | 32 字节随机盐值 |
| `role` | TEXT | DEFAULT 'user' | 角色：user/admin |
| `created_at` | INTEGER | NOT NULL | 创建时间戳 |

### audit_logs 审计日志表

| 字段名 | 类型 | 约束 | 说明 |
|---|---|---|---|
| `id` | INTEGER | PK, AUTO | 日志唯一 ID |
| `session_id` | TEXT | NOT NULL | 会话标识 |
| `user_id` | TEXT | NOT NULL | 操作用户名 |
| `client_ip` | TEXT | NOT NULL | 客户端 IP 地址 |
| `action_type` | TEXT | NOT NULL | LOGIN/LOGOFF/SEND_MSG 等 |
| `content_enc` | TEXT |  | AES 加密后的操作内容 |
| `timestamp` | INTEGER | NOT NULL | 操作时间戳，毫秒 |
| `signature` | TEXT |  | Base64 数字签名 |

### ip_bans IP 封禁表

| 字段名 | 类型 | 约束 | 说明 |
|---|---|---|---|
| `id` | INTEGER | PK, AUTO | 封禁记录 ID |
| `ip_address` | TEXT | UNIQUE, NOT NULL | 被封禁的 IP 地址 |
| `reason` | TEXT |  | 封禁原因 |
| `ban_time` | INTEGER | NOT NULL | 封禁时长，秒 |
| `created_at` | INTEGER | NOT NULL | 封禁开始时间戳 |

## 8. 测试规划

- `tests/functional/`：登录、票据签发、聊天室进入、消息收发。
- `tests/security/`：错误密码、伪造票据、重放认证器、签名篡改、IP 封禁。
- `tests/protocol/`：JSON 报文、Base64 字段、长度前缀封包。
- `tests/concurrency/`：多客户端认证、并发聊天、重复登录处理。
