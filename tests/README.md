# 测试说明

## 端到端 Smoke 测试

运行：

```powershell
python tests\e2e_smoke.py
```

脚本会自动：

- 创建临时配置文件和临时 SQLite 数据库。
- 分配临时端口并启动 AS、TGS、ChatServer。
- 使用真实 TCP 协议完成客户端认证和聊天操作。
- 测试文本群聊、图片发送与 `IMAGE_FETCH`、离线私聊、控制台管理员令牌、禁言和解除禁言。
- 结束后关闭子进程并删除临时目录。

脚本不会修改 `common/config/settings.json` 或正式数据库。
