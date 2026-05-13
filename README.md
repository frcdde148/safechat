# SafeChat

SafeChat 是一个教学用安全聊天室系统，用于演示 Kerberos V4 风格认证、登录后的加密通信、RSA 签名不可否认、管理员治理和审计追踪。

## 组成

- `client/`：普通用户 PyQt5 客户端，支持六步认证、群聊、私聊、图片消息、聊天历史、票据过期提示和重新认证。
- `admin/`：独立管理员端，支持用户、角色、会话、禁言、踢出、IP 封禁/解封、聊天记录和审计日志管理。
- `server/as_server/`：认证服务器，负责用户认证、TGT 签发、活动会话、IP 封禁和 AS 管理接口。
- `server/tgs_server/`：票据授予服务器，负责校验 TGT 并签发 ChatServer 服务票据。
- `server/chat_server/`：聊天服务器，负责服务票据认证、会话公钥绑定、消息签名校验、文本/图片消息、在线状态、离线私聊、禁言、踢出和聊天审计。
- `database/`：SQLite 初始化和 DAO。AS、TGS、ChatServer 使用独立数据库。
- `common/`：配置、协议、票据模型、DES、RSA、摘要等公共代码。
- `deployment/`：联机测试配置模板和 Windows 启动脚本。

## 默认账号

服务器首次启动会自动初始化数据库，默认账号为：

```text
admin / admin123
alice / alice123
bob   / bob123
carol / carol123
dave  / dave123
```

## 本地启动

本地开发直接使用 `common/config/settings.json`，默认地址为 `127.0.0.1`。

```powershell
python -m server.as_server.main
python -m server.tgs_server.main
python -m server.chat_server.main
python -m client.main
python -m admin.main
```

服务器启动时会自动初始化自己的数据库，不需要先手动运行 `database.init_db`。

## 联机测试

复制联机模板：

```powershell
copy deployment\connection.settings.json common\config\settings.json
```

替换模板中的：

- `AS_HOST_IP`
- `TGS_HOST_IP`
- `CHAT_HOST_IP`

服务器主机的 `bind_host` 使用 `0.0.0.0`，`public_host` 填写其他主机可访问的局域网 IP。

Windows 下也可以使用：

```text
deployment/start_as.bat
deployment/start_tgs.bat
deployment/start_chat.bat
deployment/start_client.bat
deployment/start_admin.bat
```

## 当前设计边界

- 认证流程保持 Kerberos V4 六步结构，认证前请求不要求 HMAC/RSA 签名。
- 客户端 RSA 公钥只在 `C_V_REQ` 发给 ChatServer；AS 不保存客户端公钥。
- `C_V_REQ` 的 Authenticator 包含客户端公钥摘要，ChatServer 会校验该摘要与 `public_key_pem` 一致。
- ChatServer 将公钥绑定到当前 `username + Kc,v` 会话，后续 `CHAT_SEND`、`IMAGE_SEND`、`CHAT_POLL`、`USER_LIST` 和 ChatServer 管理请求都用真实 HMAC 与该绑定公钥验签。
- 聊天文本和图片使用 `Kc,v` 加密传输；聊天列表先返回图片占位，图片正文通过签名的 `IMAGE_FETCH` 加密拉取；消息历史保留发送者 HMAC、签名和公钥用于界面展示。
- 图片消息在客户端自动显示缩略图，缩略图由后台线程解码和缩放，避免图片历史导致 UI 卡顿。
- 离线私聊会同时写入聊天历史和离线队列，发送者切换页面后仍可看到，接收者登录后可拉取。
- 只支持管理员在 admin 控制台创建用户，不支持客户端自助注册。
- 删除用户不删除聊天记录和审计日志，历史记录保留原用户名用于追溯。
