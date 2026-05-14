# SafeChat

SafeChat 是一个教学用安全聊天室系统，用于演示 Kerberos V4 风格认证、登录后的会话密钥通信、HMAC + RSA 签名、管理员治理和审计追踪。

## 组成

- `client/`：普通用户 PyQt5 客户端，支持六步认证、群聊、私聊、图片消息、会话缓存、聊天历史、票据过期提示和重新认证。
- `admin/`：独立控制台，支持用户、角色、会话、禁言、踢出、IP 封禁/解封、聊天记录和审计日志管理。
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

本地开发可以直接使用 `common/config/settings.json`。如果在单机验收，建议把 AS、TGS、ChatServer 的 `bind_host` 和 `public_host` 都设置为 `127.0.0.1`；多机联调时使用实际局域网 IP。

```powershell
python -m server.as_server.main
python -m server.tgs_server.main
python -m server.chat_server.main
python -m client.main
python -m admin.main
```

服务器启动时会自动初始化自己的数据库，不需要先手动运行 `database.init_db`。

如需手动初始化全部数据库：

```powershell
python -m database.init_db --role all
```

## 性能配置

`common/config/settings.json` 中的 `performance` 控制聊天历史和图片传输策略：

```json
"performance": {
  "history_page_size": 80,
  "encrypt_images": false
}
```

- `history_page_size`：首次进入某个会话时拉取的最近历史条数。客户端会缓存每个会话最近 N 条消息，切换回来时先显示缓存，再后台拉增量。
- `encrypt_images=false`：图片正文不做 DES 加密，仍经过 Kerberos 认证、Service Ticket、HMAC、RSA 签名和权限校验，体验更流畅。
- `encrypt_images=true`：图片正文使用 `Kc,v` 加密。为避免切换会话卡顿，客户端只显示图片占位，点击图片时才通过 `IMAGE_FETCH` 拉取并解密。

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

## 测试

推荐验收前依次运行：

```powershell
python tests\security_smoke.py
python tests\dao_smoke.py
python tests\e2e_smoke.py
python tests\perf_smoke.py
```

测试说明见 `tests/README.md`。

## 当前设计边界

- 认证流程保持 Kerberos V4 六步结构，认证前请求不要求 HMAC/RSA 签名。
- 客户端 RSA 公钥只在 `C_V_REQ` 发给 ChatServer；AS 不保存客户端公钥。
- `C_V_REQ` 的 Authenticator 包含客户端公钥摘要，ChatServer 会校验该摘要与 `public_key_pem` 一致。
- ChatServer 将公钥绑定到当前 `username + Kc,v` 会话，后续 `CHAT_SEND`、`IMAGE_SEND`、`CHAT_POLL`、`USER_LIST` 和 ChatServer 管理请求都用真实 HMAC 与该绑定公钥验签。
- 聊天文本使用 `Kc,v` 加密传输；图片正文是否加密由 `performance.encrypt_images` 控制。
- 聊天列表先返回图片占位，图片正文通过签名的 `IMAGE_FETCH` 单独拉取；图片不加密时返回 Base64，图片加密时返回 `image_cipher`。
- 客户端按会话缓存最近消息，切换会话时先显示缓存，再后台拉增量。首次进入会话时只拉最近 `history_page_size` 条。
- 图片消息在客户端显示占位或缩略图，缩略图由后台线程解码和缩放。开启图片加密时，历史图片默认按需点击加载，避免批量解密导致卡顿。
- 离线私聊会同时写入聊天历史和离线队列，发送者切换页面后仍可看到，接收者登录后可拉取。
- ChatServer 对 `USER_LIST` 使用 1 秒短缓存，并减少 `CHAT_POLL`、`IMAGE_FETCH`、控制台读列表等高频成功读操作的审计写入。
- 只支持管理员在 admin 控制台创建用户，不支持客户端自助注册。
- 删除用户不删除聊天记录和审计日志，历史记录保留原用户名用于追溯。

## 已知边界

- 本项目是课程演示系统，不是生产级安全通信系统。
- DES 和 RSA-1024 用于展示课程机制，不建议用于真实生产环境。
- ChatServer 数据库保存聊天文本和图片 Base64 明文，返回客户端时再按当前会话加密文本或按配置处理图片。
- 图片加密采用字符串级 DES，对大图片性能较差；验收演示可根据需要切换 `encrypt_images`。
- 客户端会话缓存是进程内缓存，客户端重启后会重新加载最近历史页。
