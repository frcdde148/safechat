# Config

该目录用于保存运行配置。

建议区分：

- 开发环境配置
- 局域网演示环境配置
- 各主机的地址与端口配置

## settings.json

运行时会优先读取 `common/config/settings.json`。如果文件不存在，程序会使用
`common/config/settings.py` 中的本机默认值。

字段说明：

- `bind_host`：服务端监听地址。四机部署时建议服务端机器填 `0.0.0.0`。
- `host`：服务对外公布的访问地址。四机部署时填该服务所在主机的局域网 IP。
- `port`：服务端口。
- `service_key`：TGS/ChatServer 的服务密钥。所有服务器数据库必须使用同一组值。

四机示例：

```json
{
  "as_server": {
    "bind_host": "0.0.0.0",
    "host": "192.168.1.10",
    "port": 8000
  },
  "tgs_server": {
    "bind_host": "0.0.0.0",
    "host": "192.168.1.11",
    "port": 8001,
    "service_key": "demo-tgs-key"
  },
  "chat_server": {
    "bind_host": "0.0.0.0",
    "host": "192.168.1.12",
    "port": 9000,
    "service_name": "chat_server",
    "service_key": "demo-chat-key"
  },
  "database": {
    "path": "database/chatroom.db"
  }
}
```

修改 `settings.json` 后，重新运行：

```bash
python -m database.init_db
```

`init_db` 会把 `services` 表中的 TGS 和 ChatServer 地址更新为配置文件里的
`host`/`port`，避免客户端认证后仍跳转到旧地址。
