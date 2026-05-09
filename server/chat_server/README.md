# ChatServer

启动：

```powershell
python -m server.chat_server.main
```

ChatServer 负责：

- 校验 Service Ticket。
- 完成 Kerberos 服务端双向认证。
- 管理通讯录、在线状态、禁言和踢出。
- 存储并返回群聊、私聊文本和图片消息。
- 校验登录后的消息签名。
- 记录聊天审计和管理审计。
- 维护会话撤销记录。

ChatServer 只保存用户角色副本。角色主数据以 AS 为准，admin 管理端修改角色后会同步到 ChatServer。
