# SafeChat 设计说明

SafeChat 是一个教学用安全聊天室系统，核心目标是演示 Kerberos V4 登录认证、登录后的对称加密通信，以及基于非对称签名的消息不可否认。

## 1. 进程划分

系统由五类进程组成：

- `client`：普通用户客户端，负责登录认证、群聊、私聊、图片收发和管理员入口。
- `admin`：独立管理端，复用管理员 Kerberos 登录态，向各服务器发送管理请求。
- `AS`：认证服务器，只负责用户身份认证、签发 `TGT`、维护 AS 侧用户/会话/审计数据。
- `TGS`：票据授予服务器，只负责校验 `TGT` 并签发访问 ChatServer 的服务票据。
- `ChatServer`：聊天服务器，只负责服务票据认证、在线状态、聊天消息、图片、禁言/踢出和聊天审计。

AS、TGS、ChatServer 各自使用独立 SQLite 数据库，管理端不直接访问数据库，只通过服务器提供的管理协议操作。

## 2. 数据库边界

- AS 数据库：用户账号、密码哈希、角色、登录会话、IP 封禁、AS 审计。
- TGS 数据库：服务配置、管理员角色副本、TGS 审计。
- ChatServer 数据库：服务配置、用户角色副本、聊天记录、禁言状态、踢出状态、聊天审计。

独立数据库避免三台服务端互相访问数据库文件，适合四台主机部署。初始化脚本负责一次性生成三份数据库的基础数据。

## 3. Kerberos V4 登录流程

登录认证前六步保持纯 Kerberos V4 风格，不携带 HMAC 和 RSA 签名。

1. `Client -> AS`：发送 `C_AS_REQ`，包含用户名。
2. `AS -> Client`：返回 `AS_C_REP`，包含用用户长期密钥加密的 `Kc,tgs`，以及用 TGS 服务密钥加密的 `TGT`。
3. `Client -> TGS`：发送 `C_TGS_REQ`，包含 `TGT` 和用 `Kc,tgs` 加密的 Authenticator。
4. `TGS -> Client`：返回 `TGS_C_REP`，包含用 `Kc,tgs` 加密的 `Kc,v`，以及用 ChatServer 服务密钥加密的 Service Ticket。
5. `Client -> ChatServer`：发送 `C_V_REQ`，包含 Service Ticket 和用 `Kc,v` 加密的 Authenticator。
6. `ChatServer -> Client`：返回 `V_C_REP`，包含用 `Kc,v` 加密的 `timestamp + 1`，完成双向认证。

用户名用于 AS 查询用户长期密钥。密码不直接上传给 AS，客户端用密码派生本地长期密钥来解密 AS 返回的 `Kc,tgs`；密码错误时无法解密后续票据。

## 4. 登录后安全机制

登录成功后，聊天消息使用 `Kc,v` 做对称加密传输。

需要不可否认的业务消息额外携带：

- `digest`：对明文字段做 SHA-256 摘要。
- `sig`：客户端私钥对摘要签名。
- `pubkey`：客户端公钥，用于服务端验签。

当前需要签名的消息包括：

- `CHAT_SEND`
- `IMAGE_SEND`
- `ADMIN_MUTE_USER`
- `ADMIN_UNMUTE_USER`
- `ADMIN_KICK_USER`
- `CHAT_ADMIN_LIST_MESSAGES`
- `CHAT_ADMIN_AUDIT_QUERY`
- `CHAT_ADMIN_SET_ROLE`

## 5. 管理端认证

管理员先完成普通 Kerberos 登录。随后管理端向 AS 发送 `AS_ADMIN_TOKEN_REQ`，请求体包含现有 `TGT` 和 Authenticator。

AS 校验 `TGT`、Authenticator 和管理员角色后，签发短期 `admin_token`：

```json
{
  "username": "admin",
  "expires_at": 1770000000000
}
```

AS 和 TGS 的管理 API 使用该短期 token 鉴权。ChatServer 管理 API 使用已登录的服务票据、管理员角色和消息签名鉴权。

## 6. 当前协议类型

控制消息：

- `HEARTBEAT`
- `ERROR`

认证消息：

- `C_AS_REQ`
- `AS_C_REP`
- `C_TGS_REQ`
- `TGS_C_REP`
- `C_V_REQ`
- `V_C_REP`

业务消息：

- `CHAT_SEND`
- `CHAT_POLL`
- `CHAT_RECV`
- `CHAT_ACK`
- `USER_LIST`
- `IMAGE_SEND`
- `ADMIN_MUTE_USER`
- `ADMIN_MUTE_ACK`
- `ADMIN_UNMUTE_USER`
- `ADMIN_UNMUTE_ACK`
- `ADMIN_KICK_USER`
- `ADMIN_KICK_ACK`
- `AS_ADMIN_*`
- `TGS_ADMIN_*`
- `CHAT_ADMIN_*`

项目当前不保留未实现的通用 `FILE_*` 协议。图片作为聊天消息的一种内容通过 `IMAGE_SEND` 处理。

## 7. 部署配置

所有主机和端口从 `common/config/settings.json` 读取，不应在代码中硬编码。

四台主机部署建议：

- 客户端机器：运行 `python -m client.main`。
- AS 机器：运行 `python -m server.as_server.main`。
- TGS 机器：运行 `python -m server.tgs_server.main`。
- ChatServer 机器：运行 `python -m server.chat_server.main`。

`host` 填写其他机器能够访问到的网卡 IP；本机测试可用 `127.0.0.1`。多机部署时不要使用 `localhost` 指向其他主机。
