# Database

该目录用于保存运行时数据文件，例如：

- `chatroom.db` SQLite 数据库
- `users` 用户表，保存 SHA-256 加盐密码哈希
- `audit_logs` 审计日志表，保存加密内容和 RSA 签名
- `ip_bans` IP 封禁表
- `dao/` 数据访问层
