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
- `database.as_path`：AS 使用的 SQLite 数据库，保存用户、登录会话、AS 审计。
- `database.tgs_path`：TGS 使用的 SQLite 数据库，保存服务密钥与 TGS 审计。
- `database.chat_path`：ChatServer 使用的 SQLite 数据库，保存聊天记录、离线消息、聊天审计。

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
    "path": "database/chatroom.db",
    "as_path": "database/as.db",
    "tgs_path": "database/tgs.db",
    "chat_path": "database/chat.db"
  }
}
```

修改 `settings.json` 后，本机开发可一次初始化全部数据库：

```bash
python -m database.init_db --role all
```

四机部署时，每台服务端只初始化自己的数据库：

```bash
# Host-A: AS
python -m database.init_db --role as

# Host-B: TGS
python -m database.init_db --role tgs

# Host-C: ChatServer
python -m database.init_db --role chat
```

客户端机器不需要初始化数据库。

`init_db` 按角色初始化：

- AS 数据库写入用户、TGS 服务地址和 `tgs_server.service_key`。
- TGS 数据库写入 TGS/ChatServer 服务地址与服务密钥。
- ChatServer 数据库写入 ChatServer 服务密钥、离线消息表、聊天记录表。

独立数据库部署时必须保持以下静态密钥一致：

- AS 与 TGS 的 `tgs_server.service_key` 一致。
- TGS 与 ChatServer 的 `chat_server.service_key` 一致。
