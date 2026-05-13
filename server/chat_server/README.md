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
- 记录聊天审计和管理审计。

ChatServer 只保存用户角色副本。角色主数据以 AS 为准，admin 管理端修改角色后会同步到 ChatServer。

聊天历史会保留消息文本、图片 base64、发送者 HMAC、签名和公钥，供客户端展示安全层信息。返回历史列表时先返回图片占位，图片正文通过 `IMAGE_FETCH` 使用当前 `Kc,v` 加密返回。离线私聊会同时写入聊天历史和离线队列。
