# SafeChat 联机测试配置

项目保留两种配置场景：

- 本地开发测试：使用 `common/config/settings.json`，单机运行时建议全部地址为 `127.0.0.1`。
- 联机测试：复制 `deployment/connection.settings.json` 到 `common/config/settings.json`，替换三台服务器 IP。

联机测试需要替换：

- `AS_HOST_IP`：运行 AS 的主机局域网 IP。
- `TGS_HOST_IP`：运行 TGS 的主机局域网 IP。
- `CHAT_HOST_IP`：运行 ChatServer 的主机局域网 IP。

服务器建议：

- `bind_host` 保持 `0.0.0.0`，表示监听本机所有网卡。
- `public_host` 填其他机器能访问到的局域网 IP。
- AS、TGS、ChatServer、Client、Admin 可以使用同一份联机配置文件。

启动：

```bat
start_as.bat
start_tgs.bat
start_chat.bat
start_client.bat
start_admin.bat
```

服务器启动时会自动初始化自己的数据库，不需要先手动初始化。

联机配置同样支持性能字段：

```json
"performance": {
  "history_page_size": 80,
  "encrypt_images": false
}
```

- 单机验收推荐 `bind_host=127.0.0.1`、`public_host=127.0.0.1`。
- 多机联调时服务器 `bind_host=0.0.0.0`，`public_host` 填其他主机可访问的局域网 IP。
- `encrypt_images=false` 更适合演示图片流畅体验；需要展示图片正文加密时可改为 `true`，并重启 ChatServer 和客户端。
