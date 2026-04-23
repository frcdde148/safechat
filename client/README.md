# Client

客户端负责：

- 用户登录与本地口令派生
- 与 `AS`、`TGS`、`ChatServer` 的 TCP 通信
- GUI 展示认证流程、票据和报文细节
- 使用 `Client-Service Session Key` 加密聊天消息
- 对关键聊天和文件操作生成 RSA-1024 数字签名

客户端入口：

```bash
python3 -m client.main
```
