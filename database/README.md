# 数据库

SafeChat 使用 SQLite。AS、TGS、ChatServer 各自使用独立数据库：

- `database/as.db`
- `database/tgs.db`
- `database/chat.db`

服务器启动时会自动初始化自己的数据库，不需要先手动执行初始化命令。

## AS 数据库

保存：

- 用户账号。
- salt 和 password hash。
- 用户角色主数据。
- 活动登录会话。
- IP 封禁。
- AS 审计日志。

## TGS 数据库

保存：

- TGS 服务配置。
- ChatServer 服务配置。
- TGS 审计日志。

## ChatServer 数据库

保存：

- 通讯录用户角色副本。
- 群聊和私聊消息。
- 图片数据。
- 离线私聊消息。
- 禁言规则。
- 会话撤销记录。
- ChatServer 审计日志。

删除用户不会删除聊天记录和审计日志，历史数据保留原用户名用于追溯。
