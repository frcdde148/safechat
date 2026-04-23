# SafeChat 网络安全课程设计

SafeChat 是一个基于 Kerberos V4 流程并扩展数字签名与摘要校验机制的局域网认证聊天室系统。系统包含 `Client`、`AS`、`TGS`、`ChatServer` 四类实体，使用 TCP Socket、JSON + Base64 报文、长度前缀封包和多线程模型完成多用户并发通信。

## 架构概览

项目采用客户端层、服务层、数据层的三层架构：

- `client/`：PyQt5 客户端、控制逻辑、网络通信、票据与加密处理。
- `server/`：AS 认证服务器、TGS 票据授予服务器、ChatServer 聊天服务器。
- `common/`：协议、DES/RSA/SHA-256/AES 封装、配置、模型和工具。
- `database/`：SQLite 初始化脚本、DAO 和数据库文件。
- `logs/`、`tests/`、`docs/`、`scripts/`：日志、测试、文档和辅助脚本。

## 安全设计

- Kerberos V4 六步认证流程用于身份认证、票据签发和会话密钥分发。
- DES 用于课程设计要求下的票据与会话消息机密性保护。
- RSA-1024 用于关键操作签名与验签，覆盖 `CHAT_SEND`、`CHAT_RECV`、`CHAT_ACK` 和 `FILE_*` 消息。
- SHA-256 用于用户密码加盐哈希和摘要校验。
- 审计日志记录登录、登出、消息操作、票据异常和非法访问等关键事件。

## 初始化数据库

```bash
python -m database.init_db
```
