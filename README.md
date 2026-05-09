# SafeChat

SafeChat 是一个教学用安全聊天室系统，用于演示 Kerberos V4 登录认证、登录后的加密聊天、消息签名不可否认、管理员管理和审计追溯。

## 组成

- `client/`：普通用户 PyQt5 客户端，支持 Kerberos 登录、群聊、私聊、图片、聊天历史和重新认证。
- `admin/`：独立管理员管理端，支持创建/删除用户、重置密码、角色管理、禁言、踢出、IP 封禁、审计查询和聊天记录追溯。
- `server/as_server/`：AS 认证服务器，负责用户长期密钥、TGT、管理员 token、账号和 AS 审计。
- `server/tgs_server/`：TGS 票据服务器，负责校验 TGT 并签发 ChatServer 服务票据。
- `server/chat_server/`：聊天服务器，负责服务票据认证、聊天消息、图片、在线状态、禁言、踢出、会话撤销和聊天审计。
- `database/`：SQLite 初始化和 DAO。AS、TGS、ChatServer 各自使用独立数据库。
- `common/`：配置、协议、票据模型、DES/RSA/SHA-256 等公共代码。
- `deployment/`：联机测试配置模板和 Windows 启动脚本。

## 默认账号

服务器首次启动会自动初始化数据库。AS 默认创建：

```text
admin / admin123
alice / alice123
bob   / bob123
carol / carol123
dave  / dave123
```

## 本地启动

本地开发测试直接使用 `common/config/settings.json`，默认全部地址为 `127.0.0.1`。

分别启动：

```powershell
python -m server.as_server.main
python -m server.tgs_server.main
python -m server.chat_server.main
python -m client.main
python -m admin.main
```

服务器启动时会自动初始化自己的数据库，不需要先手动运行 `database.init_db`。

## 联机测试

复制模板：

```powershell
copy deployment\connection.settings.json common\config\settings.json
```

替换模板中的：

- `AS_HOST_IP`
- `TGS_HOST_IP`
- `CHAT_HOST_IP`

四台机器可以使用同一份联机配置。服务器机器的 `bind_host` 保持 `0.0.0.0`，`public_host` 填对应服务器局域网 IP。

Windows 下可双击：

```text
deployment/start_as.bat
deployment/start_tgs.bat
deployment/start_chat.bat
deployment/start_client.bat
deployment/start_admin.bat
```

## 当前设计边界

- 认证前六步保持 Kerberos V4 风格，不带 HMAC 和 RSA 签名。
- 登录后的聊天、图片和管理请求带摘要和 RSA 签名。
- 只支持管理员在 admin 管理端创建用户，不支持客户端自助注册。
- 用户名创建后不可修改。
- 管理员不能修改自己的角色，也不能删除自己。
- 至少保留一个管理员。
- 删除用户不删除聊天记录和审计日志，历史记录保留原用户名用于追溯。
