# TGS Server

启动：

```powershell
python -m server.tgs_server.main
```

TGS 负责：

- 校验 AS 签发的 `TGT`。
- 校验客户端 Authenticator。
- 生成 `Kc,v`。
- 签发访问 ChatServer 的 Service Ticket。
- 返回 ChatServer 对外地址。
- 记录 TGS 审计日志。

TGS 管理接口只接受加密管理请求：客户端提交 `ticket_tgs`、`authenticator_c` 和 `admin_cipher`，其中 `admin_cipher` 使用 `Kc,tgs` 加密并包含 `admin_token` 与业务字段。
