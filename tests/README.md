# 测试说明

## 协议安全 Smoke 测试

运行：

```powershell
python tests\security_smoke.py
```

覆盖：

- 协议正文 canonical JSON 与字段顺序无关。
- HMAC + RSA 签名正常通过。
- 篡改正文、篡改 HMAC、错误 HMAC 密钥、错误公钥、错误私钥签名都会失败。

## DAO Smoke 测试

运行：

```powershell
python tests\dao_smoke.py
```

覆盖：

- 聊天历史最近页查询和增量查询。
- 私聊历史读取权限。
- 禁言规则新增、读取和撤销。
- 会话撤销新增、读取和清理。

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
- 测试控制台踢出用户后，被踢用户继续轮询会收到会话撤销错误。
- 结束后关闭子进程并删除临时目录。

脚本不会修改 `common/config/settings.json` 或正式数据库。

## 性能 Smoke 测试

运行：

```powershell
python tests\perf_smoke.py
```

覆盖：

- `encrypt_images=false/true` 两种配置。
- 写入 100 条群聊文本。
- 拉取最近历史页。
- 空轮询平均耗时。
- `USER_LIST` 短缓存平均耗时。
- 控制台查询最近消息。
- 图片发送和 `IMAGE_FETCH` 拉取图片。

该测试会输出耗时，并使用宽松阈值检查明显性能回退。

## 建议执行顺序

```powershell
python tests\security_smoke.py
python tests\dao_smoke.py
python tests\e2e_smoke.py
python tests\perf_smoke.py
```
