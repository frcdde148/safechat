# ChatServer

聊天室服务端负责：

- 校验 `Service Ticket`
- 完成双向认证
- 管理在线用户
- 广播聊天消息
- 校验 `CHAT_SEND`、`CHAT_RECV`、`CHAT_ACK` 和 `FILE_*` 消息签名
- 记录聊天日志、审计日志和非法访问日志
