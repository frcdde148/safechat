# 客户端界面

PyQt5 客户端界面模块：

- `login_view.py`：登录页，输入用户名、密码和 AS 地址。
- `auth_flow_view.py`：Kerberos 六步认证流程和报文详情。
- `chat_view.py`：聊天室主界面、通讯录、消息气泡、图片缩略图/原图预览、安全状态和重新认证按钮。
- `main_window.py`：登录页和聊天室切换，协调认证、轮询、发送、图片上传和重新认证。
- `styles.py`：统一样式。

图片缩略图由 `chat_view.py` 的后台线程生成，避免图片历史阻塞主界面。
