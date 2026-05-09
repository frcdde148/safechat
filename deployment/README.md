# SafeChat 联机测试配置

项目只保留两种配置场景：

- 本地开发测试：使用 `common/config/settings.json`，全部地址为 `127.0.0.1`。
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
