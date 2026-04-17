# Client

客户端负责：

- 用户登录与本地口令派生
- 与 `AS`、`TGS`、`Service Server` 的 TCP 通信
- GUI 展示认证流程、票据和报文细节
- 使用 `Client-Service Session Key` 加密聊天消息
