# AS Server

启动：

```powershell
python -m server.as_server.main
```

AS 负责：

- 用户身份认证。
- 根据用户密码哈希派生长期密钥。
- 签发 TGT。
- 返回 TGS 对外地址。
- 维护普通客户端活动登录会话。
- 检查 IP 封禁状态。
- 签发短期 `admin_token`。
- 处理用户创建、删除、角色设置、重置密码、IP 封禁/解封和会话失效。
- 记录 AS 审计日志。

当前版本中，客户端 RSA 公钥不发送给 AS，AS 也不保存客户端公钥。公钥只在 `C_V_REQ` 中发送给 ChatServer 并绑定到聊天会话。

AS 是用户和角色的主权限源。
AS 管理接口除 `AS_ADMIN_TOKEN_REQ` 外只接受加密管理请求：客户端提交 `ticket_tgs`、`authenticator_c` 和 `admin_cipher`，其中 `admin_cipher` 使用 `Kc,tgs` 加密并包含 `admin_token` 与业务字段。
