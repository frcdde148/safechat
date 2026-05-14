# SafeChat 设计说明

## 目标

SafeChat 用于课程设计演示：

- Kerberos V4 风格六步认证。
- 登录后基于会话密钥 `Kc,v` 的加密通信。
- 基于 RSA 的请求签名和不可否认。
- 管理员用户治理、会话治理、IP 封禁和审计追踪。
- 本地或多主机联机部署。

## 进程与数据边界

系统包含五类进程：

- `client`：普通用户客户端。
- `admin`：管理员控制台。
- `AS`：认证服务器。
- `TGS`：票据授予服务器。
- `ChatServer`：聊天服务器。

数据库边界：

- AS 数据库：用户、密码哈希、角色主数据、活动会话、IP 封禁、AS 审计。
- TGS 数据库：服务配置、TGS 审计。
- ChatServer 数据库：用户角色副本、聊天记录、图片 Base64 数据、离线消息、禁言规则、会话撤销、聊天审计。

admin 控制台不直接访问 SQLite，只通过服务器管理协议操作。

## Kerberos 认证流程

认证前六步保持 Kerberos V4 风格，不要求 HMAC 和 RSA 签名。

1. `Client -> AS`：`C_AS_REQ` 请求 TGT。
2. `AS -> Client`：`AS_C_REP` 返回由用户长期密钥加密的 `Kc,tgs` 和 TGT。
3. `Client -> TGS`：`C_TGS_REQ` 携带 TGT 和 Authenticator 请求 ChatServer 服务票据。
4. `TGS -> Client`：`TGS_C_REP` 返回由 `Kc,tgs` 加密的 `Kc,v` 和服务票据。
5. `Client -> ChatServer`：`C_V_REQ` 携带服务票据、Authenticator、客户端会话 ID 和客户端 RSA 公钥；Authenticator 中包含该公钥的 SHA-256 摘要。
6. `ChatServer -> Client`：`V_C_REP` 返回 `ts_5 + 1`，完成双向认证。

密码不直接上传给 AS。客户端根据密码和 AS 返回的 salt 派生长期密钥，用于解密 AS 响应。密码错误时无法解密 `Kc,tgs`。

## 公钥与签名

当前版本只在 `C_V_REQ` 中向 ChatServer 发送客户端 RSA 公钥。AS 不接收、不保存客户端公钥。

ChatServer 成功处理 `C_V_REQ` 后，先校验 Authenticator 中的公钥摘要与 `public_key_pem` 一致，再将公钥绑定到当前 `username + Kc,v` 会话。后续请求使用真实 HMAC 和同一绑定公钥验签：

- `CHAT_SEND`
- `CHAT_POLL`
- `USER_LIST`
- `IMAGE_SEND`
- `IMAGE_FETCH`
- `ADMIN_MUTE_USER`
- `ADMIN_UNMUTE_USER`
- `ADMIN_KICK_USER`
- `CHAT_ADMIN_LIST_MESSAGES`
- `CHAT_ADMIN_AUDIT_QUERY`
- `CHAT_ADMIN_SET_ROLE`
- `CHAT_ADMIN_DELETE_USER`

请求体先用 `Kc,v` 计算 `HMAC-SHA256`，再由客户端私钥签名。ChatServer 只信任当前认证会话绑定的公钥，不再从 AS 查询公钥，也不依赖每条消息附带的公钥。

## 聊天、历史与图片

- 文本消息使用 `Kc,v` 加密传输。
- 图片正文由 `performance.encrypt_images` 控制：关闭时传输 Base64 明文，开启时使用 `Kc,v` 加密图片 Base64。
- 聊天历史保存明文文本、图片 Base64、HMAC、签名和发送者公钥，便于客户端展示安全层信息；返回给客户端时文本使用当前 `Kc,v` 加密。
- `CHAT_POLL` 只返回图片占位和文件名，不返回图片正文；图片正文通过单独的 `IMAGE_FETCH` 拉取。
- 群聊和在线私聊直接写入聊天历史。
- 离线私聊同时写入聊天历史和离线队列，发送者和接收者都能在后续会话中看到。
- 客户端按会话缓存最近 `history_page_size` 条已解密消息。切换会话时先显示缓存，再后台拉增量；首次进入会话时只拉最近一页历史。
- 图片不加密时，客户端可自动拉取图片正文并生成缩略图；图片加密时，历史图片默认只显示占位，点击时才拉取、解密并查看原图，避免批量解密阻塞 UI。

## 会话与在线状态

- AS 维护活动登录会话，并通过心跳更新 `last_seen`。
- 普通客户端同一账号只允许一个活跃登录。旧会话超时后，新登录会使旧会话失效。
- ChatServer 维护内存在线表，并根据心跳超时清理离线状态。
- ChatServer 对 `USER_LIST` 使用 1 秒短缓存，降低多客户端同时刷新联系人列表时的数据库压力。
- 票据过期或会话被管理员撤销时，客户端提示重新认证。

## 控制台

管理员先完成普通 Kerberos 登录，再向 AS 请求短期 `admin_token`。

- AS/TGS 管理接口使用 `admin_token` 鉴权。
- ChatServer 管理接口使用 Service Ticket、请求签名和 ChatServer 本地管理员角色副本鉴权。

账号规则：

- 只能由管理员创建用户。
- 不支持客户端自助注册。
- 用户名创建后不可修改。
- 管理员可以重置用户密码。
- 重置密码会使用户 AS 会话失效，并撤销 ChatServer 聊天会话。
- 管理员不能修改自己的角色，不能删除自己。
- 不能降级或删除最后一个管理员。
- 删除用户会删除 AS 账号和 ChatServer 联系人副本，但保留聊天记录和审计日志。

## IP 封禁

IP 封禁由 AS 管理并在登录阶段生效。封禁记录包含 IP、原因、创建时间、封禁时长和过期时间。控制台支持查看封禁列表和解除封禁。

## 配置与部署

保留两种配置场景：

- 本地开发或单机验收：`bind_host` 和 `public_host` 建议使用 `127.0.0.1`。
- 联机测试：复制 `deployment/connection.settings.json` 到 `common/config/settings.json`，替换 AS、TGS、ChatServer 三台服务器 IP。

字段说明：

- `bind_host`：服务器监听地址。本地填 `127.0.0.1`，联机服务器填 `0.0.0.0`。
- `public_host`：其他主机访问该服务时使用的地址。
- `port`：服务端口。

性能相关字段：

- `performance.history_page_size`：首次进入会话时返回的最近历史条数，默认 80。
- `performance.encrypt_images`：是否加密图片正文。关闭时图片传输更快，开启时图片正文使用 `Kc,v` 加密。

## 审计策略

系统保留安全事件、管理操作、消息写入和离线消息存储审计。为降低 SQLite 写锁压力，以下高频成功读操作不逐条写审计：

- `CHAT_POLL`
- `USER_LIST`
- `IMAGE_FETCH`
- `CHAT_ADMIN_LIST_MESSAGES`
