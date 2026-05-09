# 配置说明

运行时只读取一个实际配置文件：

```text
common/config/settings.json
```

项目只考虑两种场景：

- 本地开发测试：`settings.json` 使用 `127.0.0.1`。
- 联机测试：使用 `deployment/connection.settings.json` 作为模板，复制到 `common/config/settings.json` 后替换 IP。

## 字段

- `bind_host`：服务器监听地址。本地测试填 `127.0.0.1`；联机测试服务器填 `0.0.0.0`。
- `public_host`：对外访问地址。本地测试填 `127.0.0.1`；联机测试填对应服务器的局域网 IP。
- `port`：端口。
- `service_key`：TGS/ChatServer 服务密钥。所有主机必须使用同一组值。

配置文件只使用 `bind_host`、`public_host` 和 `port` 描述地址，不再使用 `host` 字段。

## 谁需要知道什么

- 客户端和 admin 管理端只直接连接 AS。
- AS 需要把 TGS 的 `public_host/port` 写入票据响应。
- TGS 需要把 ChatServer 的 `public_host/port` 写入票据响应。
- ChatServer 只需要自己的监听地址和服务密钥。

为了联机测试简单，推荐四台机器都复制同一份 `connection.settings.json`，只替换三台服务器 IP。
