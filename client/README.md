# SafeChat 客户端

启动：

```powershell
python -m client.main
```

客户端负责：

- 输入用户名、密码和 AS 地址。
- 展示 Kerberos V4 六步认证过程和报文细节。
- 在 `C_V_REQ` 中把本次客户端 RSA 公钥发送给 ChatServer。
- 进入群聊大厅，双击通讯录用户进入私聊。
- 发送加密文本；图片正文是否加密由 `performance.encrypt_images` 控制。
- 拉取群聊、私聊、离线消息和聊天历史。
- 按会话缓存最近消息，切换会话时先显示缓存，再后台拉取增量。
- 展示安全回执、票据状态、会话密钥状态和重新认证入口。

图片消息会显示占位或缩略图。缩略图由后台线程解码和缩放。`encrypt_images=false` 时客户端可自动拉取图片正文并生成缩略图；`encrypt_images=true` 时历史图片默认点击后再拉取和解密，避免大量图片历史导致界面卡顿。

认证完成后，客户端只保存本次会话需要的 TGT、Service Ticket、`Kc,tgs` 和 `Kc,v`。如果票据过期或会话被管理员撤销，客户端会提示重新认证。
