# ChatServer

启动：

```powershell
python -m server.chat_server.main
```

ChatServer 负责：

- 校验 Service Ticket。
- 完成 Kerberos 服务端双向认证。
- 在 `C_V_REQ` 中接收客户端 RSA 公钥，校验 Authenticator 中的公钥摘要，并绑定到当前 `username + Kc,v` 会话。
- 校验登录后的文本、图片发送、图片拉取、轮询、联系人列表和管理请求签名。
- 管理通讯录、在线状态、禁言、踢出和会话撤销。
- 存储并返回群聊、私聊、离线私聊和图片消息。
- 记录安全事件、消息写入和管理操作审计。

ChatServer 只保存用户角色副本。角色主数据以 AS 为准，控制台修改角色后会同步到 ChatServer。

聊天历史会保留消息文本、图片 Base64、发送者 HMAC、签名和公钥，供客户端展示安全层信息。返回历史列表时先返回图片占位，图片正文通过 `IMAGE_FETCH` 单独返回：

- `performance.encrypt_images=false`：返回 `image_data`，不额外加密图片正文。
- `performance.encrypt_images=true`：返回当前请求者 `Kc,v` 加密后的 `image_cipher`。

离线私聊会同时写入聊天历史和离线队列。

性能策略：

- `CHAT_POLL` 支持 `history_mode=latest` 和 `limit`，首次进入会话只返回最近一页。
- `USER_LIST` 使用 1 秒内存缓存，登录、踢人、禁言、解禁、角色变更、删除用户、会话撤销等状态变化会清空缓存。
- 高频成功读操作（`CHAT_POLL`、`IMAGE_FETCH`、`CHAT_ADMIN_LIST_MESSAGES`）不逐条写审计，减少 SQLite 写锁压力；失败和管理写操作仍写审计。
