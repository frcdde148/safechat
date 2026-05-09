# SafeChat 设计说明

## 1. 目标

SafeChat 用于课程设计演示：

- Kerberos V4 六步登录认证。
- 登录后的会话密钥加密通信。
- RSA 签名实现消息不可否认。
- 管理员管理、审计和聊天记录追溯。
- 四台主机联机部署。

## 2. 进程和数据库

系统包含五类进程：

- `client`：普通用户客户端。
- `admin`：管理员管理端。
- `AS`：认证服务器。
- `TGS`：票据授予服务器。
- `ChatServer`：聊天服务器。

数据库边界：

- AS 数据库：用户、密码哈希、角色主数据、登录会话、IP 封禁、AS 审计。
- TGS 数据库：服务配置、TGS 审计。
- ChatServer 数据库：用户角色副本、聊天记录、图片、禁言、会话撤销、聊天审计。

admin 管理端不直接访问数据库，只通过服务器管理协议操作。

## 3. Kerberos V4 登录流程

认证前六步不带 HMAC 和 RSA 签名：

1. `Client -> AS`：`C_AS_REQ`，包含用户名。
2. `AS -> Client`：`AS_C_REP`，返回用用户长期密钥加密的 `Kc,tgs`，以及用 TGS 服务密钥加密的 `TGT`。
3. `Client -> TGS`：`C_TGS_REQ`，包含 `TGT` 和用 `Kc,tgs` 加密的 Authenticator。
4. `TGS -> Client`：`TGS_C_REP`，返回用 `Kc,tgs` 加密的 `Kc,v`，以及用 ChatServer 服务密钥加密的 Service Ticket。
5. `Client -> ChatServer`：`C_V_REQ`，包含 Service Ticket 和用 `Kc,v` 加密的 Authenticator。
6. `ChatServer -> Client`：`V_C_REP`，返回用 `Kc,v` 加密的 `timestamp + 1`，完成双向认证。

密码不直接上传给 AS。客户端用密码和 AS 返回的 salt 派生长期密钥，用来解密 `Kc,tgs`。密码错误时无法解密后续票据。

## 4. 登录后安全

登录后业务消息使用 `Kc,v` 对称加密。需要不可否认的请求额外携带：

- `hmac`：当前实现中存放请求体摘要。
- `sig`：客户端私钥对摘要签名。
- `pubkey`：客户端公钥。

当前签名消息包括：

- `CHAT_SEND`
- `IMAGE_SEND`
- `ADMIN_MUTE_USER`
- `ADMIN_UNMUTE_USER`
- `ADMIN_KICK_USER`
- `CHAT_ADMIN_LIST_MESSAGES`
- `CHAT_ADMIN_AUDIT_QUERY`
- `CHAT_ADMIN_SET_ROLE`
- `CHAT_ADMIN_DELETE_USER`

## 5. 管理端

管理员先完成普通 Kerberos 登录，然后向 AS 发送 `AS_ADMIN_TOKEN_REQ`。AS 校验 TGT、Authenticator 和管理员角色后，签发短期 `admin_token`。

AS/TGS 管理接口使用 `admin_token` 鉴权。ChatServer 管理接口使用 Service Ticket、请求签名和 ChatServer 本地角色副本鉴权。

账号管理规则：

- 只允许 admin 管理端创建用户。
- 不支持客户端自助注册。
- 不支持修改用户名。
- 管理员可以重置用户密码。
- 重置密码后 AS 使该用户会话失效，ChatServer 撤销该用户聊天会话。
- 管理员不能修改自己的角色。
- 管理员不能删除自己。
- 不能降级或删除最后一个管理员。
- 删除用户时，AS 删除账号，ChatServer 删除通讯录副本；聊天记录和审计日志保留。

## 6. 会话撤销

ChatServer 使用 `session_revocations` 记录被管理员踢出、重置密码或删除触发的撤销状态。

被撤销用户即使继续持有旧 Service Ticket，后续以下请求也会被拒绝：

- 发文本消息。
- 发图片。
- 拉取消息。
- 刷新通讯录。
- 管理请求。

用户必须重新完成 Kerberos 登录。新的 `C_V_REQ` 成功后，ChatServer 清除该用户撤销状态。

## 7. 配置和部署

只保留两种配置场景：

- 本地开发测试：`common/config/settings.json`，全部使用 `127.0.0.1`。
- 联机测试：复制 `deployment/connection.settings.json` 为 `common/config/settings.json`，替换三台服务器 IP。

地址字段：

- `bind_host`：服务器监听地址。本地填 `127.0.0.1`，联机服务器填 `0.0.0.0`。
- `public_host`：其他机器访问该服务时使用的地址。
- `port`：端口。

四台主机建议：

- AS 主机运行 `python -m server.as_server.main`。
- TGS 主机运行 `python -m server.tgs_server.main`。
- ChatServer 主机运行 `python -m server.chat_server.main`。
- 客户端主机运行 `python -m client.main` 或 `python -m admin.main`。
