# AS Server

启动：

```powershell
python -m server.as_server.main
```

AS 负责：

- 用户身份认证。
- 根据用户密码哈希派生长期密钥。
- 签发 `TGT`。
- 返回 TGS 对外地址。
- 签发短期 `admin_token`。
- 处理用户创建、删除、角色设置、重置密码、IP 封禁和会话失效。
- 记录 AS 审计日志。

AS 是用户和角色的主权限源。
