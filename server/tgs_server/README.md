# TGS Server

票据授权服务器负责：

- 校验 `TGT`
- 校验客户端 `Authenticator`
- 生成 `Client-Service Session Key`
- 签发聊天室服务票据 `Service Ticket`
- 记录票据签发、异常票据和非法请求审计日志
