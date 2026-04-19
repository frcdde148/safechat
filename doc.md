# 基于 Kerberos V4 的局域网认证聊天室系统设计文档

  

## 1. 绪论

  

### 1.1 项目背景

  

身份认证是网络安全系统中的基础能力。传统的用户名口令认证方式如果设计不当，容易出现口令重复传输、服务端分散保存用户凭据、认证结果难以复用等问题。Kerberos 是一种基于可信第三方、对称密钥和票据机制的网络认证协议，能够在不直接向业务服务暴露用户口令的前提下完成身份认证，并支持面向多服务场景的单点登录思想。

  

本课程设计以 Kerberos V4 为核心协议模型，在局域网环境下实现一个真实可运行的认证系统。系统包含 `Client`、`AS`、`TGS` 和 `Service Server` 四类实体，并以受保护聊天室作为业务服务场景。客户端只有完成 Kerberos V4 的完整认证流程后，才能进入聊天室发送和接收消息。

  

### 1.2 项目目标

  

本项目目标是在局域网多主机环境中实现一个严格遵循 Kerberos V4 核心流程的认证聊天室系统，主要目标包括：

  

- 实现 `Client`、`AS`、`TGS`、`Service Server` 四类独立实体。

- 实现 `Client-AS`、`Client-TGS`、`Client-Service` 三阶段认证流程。

- 实现 `TGT`、`Service Ticket`、`Authenticator` 和会话密钥机制。

- 实现服务端与客户端之间的双向认证。

- 实现受 Kerberos V4 保护的公共聊天室服务。

- 实现聊天消息基于会话密钥的加密传输。

- 使用 `PyQt/PySide` 图形界面展示认证报文、票据和加解密细节。

- 支持四个预置用户分别从四台主机访问同一聊天室服务。

  

### 1.3 项目定位

  

本系统面向课程设计和教学演示，重点在于 Kerberos V4 认证流程的正确实现、局域网环境下的真实可运行性以及认证过程的可视化展示。系统不追求工业级高可用、跨域认证、复杂权限模型和大规模性能优化。

  

## 2. 需求分析

  

### 2.1 功能需求

  

| 编号 | 功能项 | 说明 |

|---|---|---|

| F-01 | 用户登录 | 用户在客户端输入预置用户名和密码发起认证 |

| F-02 | AS 认证 | `AS` 验证用户身份并签发 `TGT` |

| F-03 | TGS 授权 | `TGS` 验证 `TGT` 后签发聊天室服务票据 |

| F-04 | 服务认证 | `Service Server` 验证服务票据和认证器 |

| F-05 | 双向认证 | 服务端返回 `timestamp + 1`，客户端验证服务端身份 |

| F-06 | 聊天接入 | 认证成功后客户端进入公共聊天室 |

| F-07 | 消息加密 | 聊天消息使用 `Client-Service Session Key` 加密传输 |

| F-08 | 在线管理 | 服务端维护当前在线用户列表 |

| F-09 | 重复登录控制 | 同一用户只保留一个在线会话 |

| F-10 | 日志记录 | 记录认证日志、异常访问日志和聊天日志 |

| F-11 | GUI 展示 | 展示认证阶段、报文字段、票据内容和加解密结果 |

  

### 2.2 非功能需求

  

| 类别 | 要求 |

|---|---|

| 运行环境 | 局域网多主机环境 |

| 开发语言 | Python |

| 通信方式 | TCP Socket |

| 客户端界面 | PyQt 或 PySide |

| 数据存储 | SQLite 保存用户、服务和认证日志 |

| 运行规模 | 四个预置用户，四个客户端实例 |

| 可演示性 | GUI 应能清晰展示认证数据流 |

| 安全性 | 具备票据加密、时间戳校验、双向认证和重放防护 |

  

### 2.3 约束条件

  

- 系统预置四个用户，不实现用户注册功能。

- 聊天室为单服务实例、单公共房间。

- 不实现私聊、多房间、离线消息和文件传输。

- 不实现跨 `Realm` 认证。

- 不专门实现断线重连，掉线后需要重新认证。

- 不实现严格意义上的不可否认性。Kerberos 提供双向认证，但不提供基于数字签名的不可否认能力。

  

## 3. 总体设计

  

### 3.1 系统角色

  

| 角色 | 职责 |

|---|---|

| `Client` | 发起认证请求、保存票据、访问聊天室服务、展示认证过程 |

| `AS` | 验证用户身份，签发 `TGT` 和 `Client-TGS Session Key` |

| `TGS` | 验证 `TGT`，签发 `Service Ticket` 和 `Client-Service Session Key` |

| `Service Server` | 验证服务票据，完成双向认证，提供聊天室服务 |

  

### 3.2 逻辑架构

  

```text

+----------+       +---------+       +---------+       +----------------+

|  Client  | <---> |   AS    |       |   TGS   |       | Service Server |

|  GUI     |       |         |       |         |       | Chat Service   |

+----------+       +---------+       +---------+       +----------------+

     |                  |                 |                    |

     | 1. 请求 TGT       |                 |                    |

     |----------------->|                 |                    |

     | 2. 返回 TGT       |                 |                    |

     |<-----------------|                 |                    |

     |                                    |                    |

     | 3. 使用 TGT 请求 Service Ticket     |                    |

     |----------------------------------->|                    |

     | 4. 返回 Service Ticket             |                    |

     |<-----------------------------------|                    |

     |                                                         |

     | 5. 提交 Service Ticket 访问聊天室                         |

     |-------------------------------------------------------->|

     | 6. 双向认证成功，进入聊天室                                |

     |<--------------------------------------------------------|

```

  

### 3.3 工程架构

  

项目采用四个可运行程序和一个公共模块的方式组织：

  

```text

client/             客户端程序与 GUI

as_server/          AS 认证服务器

tgs_server/         TGS 票据授权服务器

service_server/     聊天室服务端

common/             公共模型、协议、加密、数据库和日志工具

config/             配置文件

data/               SQLite 数据库

logs/               认证日志和聊天日志

scripts/            初始化脚本

tests/              测试代码

```

  

## 4. Kerberos V4 协议设计

  

### 4.1 符号约定

  

| 符号 | 含义 |

|---|---|

| `C` | 客户端用户 |

| `AS` | 认证服务器 |

| `TGS` | 票据授权服务器 |

| `V` | 业务服务端，即聊天室服务 |

| `IDc` | 客户端用户标识 |

| `IDtgs` | TGS 标识 |

| `IDv` | 服务端标识 |

| `ADc` | 客户端网络地址 |

| `Kv` | 服务端长期密钥 |

| `Ktgs` | TGS 长期密钥 |

| `Kc` | 用户长期密钥 |

| `Kc,tgs` | Client 与 TGS 的会话密钥 |

| `Kc,v` | Client 与 Service 的会话密钥 |

| `TS` | 时间戳 |

| `Lifetime` | 票据有效期 |

  

### 4.2 核心数据结构

  

#### 4.2.1 TGT

  

`TGT` 由 `AS` 签发，由 `TGS` 长期密钥 `Ktgs` 加密。客户端无法解密 `TGT`，只能转交给 `TGS` 使用。

  

```json

{

  "ticket_type": "TGT",

  "client_id": "alice",

  "client_addr": "192.168.1.11",

  "tgs_id": "tgs_server",

  "session_key": "Kc,tgs",

  "timestamp": 1710000000,

  "lifetime": 300

}

```

  

#### 4.2.2 Service Ticket

  

`Service Ticket` 由 `TGS` 签发，由服务端长期密钥 `Kv` 加密。客户端无法解密该票据，只能转交给 `Service Server`。

  

```json

{

  "ticket_type": "SERVICE_TICKET",

  "client_id": "alice",

  "client_addr": "192.168.1.11",

  "service_id": "chat_service",

  "session_key": "Kc,v",

  "timestamp": 1710000060,

  "lifetime": 180

}

```

  

#### 4.2.3 Authenticator

  

`Authenticator` 由客户端生成，用于证明请求者持有相应会话密钥，并防止票据被简单重放。

  

```json

{

  "client_id": "alice",

  "client_addr": "192.168.1.11",

  "timestamp": 1710000070

}

```

  

### 4.3 三阶段认证流程

  

#### 4.3.1 Client-AS 阶段

  

客户端向 `AS` 请求 `TGT`。

  

```text

C -> AS: IDc, IDtgs, TS1

AS -> C: E(Kc, Kc,tgs, IDtgs, TS2, Lifetime, TGT)

TGT = E(Ktgs, Kc,tgs, IDc, ADc, IDtgs, TS2, Lifetime)

```

  

处理逻辑：

  

- `AS` 查询用户表，确认 `IDc` 是否存在。

- `AS` 生成 `Kc,tgs`。

- `AS` 使用用户长期密钥 `Kc` 加密返回给客户端的敏感信息。

- `AS` 使用 `Ktgs` 加密生成 `TGT`。

  

#### 4.3.2 Client-TGS 阶段

  

客户端使用 `TGT` 向 `TGS` 请求聊天室服务票据。

  

```text

C -> TGS: IDv, TGT, Authenticator_c

Authenticator_c = E(Kc,tgs, IDc, ADc, TS3)

TGS -> C: E(Kc,tgs, Kc,v, IDv, TS4, Lifetime, ServiceTicket)

ServiceTicket = E(Kv, Kc,v, IDc, ADc, IDv, TS4, Lifetime)

```

  

处理逻辑：

  

- `TGS` 使用 `Ktgs` 解密 `TGT`。

- `TGS` 使用 `Kc,tgs` 解密 `Authenticator_c`。

- `TGS` 校验客户端标识、客户端地址、时间戳和票据有效期。

- `TGS` 查询服务表，确认 `IDv` 是否存在。

- `TGS` 生成 `Kc,v`。

- `TGS` 使用 `Kv` 加密生成 `Service Ticket`。

  

#### 4.3.3 Client-Service 阶段

  

客户端使用 `Service Ticket` 访问聊天室服务。

  

```text

C -> V: ServiceTicket, Authenticator_c

Authenticator_c = E(Kc,v, IDc, ADc, TS5)

V -> C: E(Kc,v, TS5 + 1)

```

  

处理逻辑：

  

- `Service Server` 使用 `Kv` 解密 `Service Ticket`。

- `Service Server` 使用 `Kc,v` 解密 `Authenticator_c`。

- `Service Server` 校验客户端标识、客户端地址、时间戳和票据有效期。

- `Service Server` 检查认证器是否已被使用，防止重放攻击。

- 验证通过后，服务端返回 `TS5 + 1` 的加密结果。

- 客户端解密验证成功后，确认服务端身份可信，进入聊天室。

  

### 4.4 时间与生命周期参数

  

| 参数 | 建议值 | 说明 |

|---|---:|---|

| 允许时钟偏差 | 120 秒 | 多主机演示环境中允许的最大时间误差 |

| `TGT` 有效期 | 300 秒 | 用于向 `TGS` 申请服务票据 |

| `Service Ticket` 有效期 | 180 秒 | 用于访问聊天室服务 |

| `Authenticator` 有效期 | 60 秒 | 防止长期重放 |

  

## 5. 通信与报文设计

  

### 5.1 通信协议

  

系统采用 `TCP Socket` 进行通信。应用层报文统一使用 `JSON` 表示，密文字段使用 `Base64` 编码后放入 JSON 字段中。

  

每条 TCP 消息建议使用长度前缀封包，避免粘包和半包问题：

  

```text

4 字节消息长度 + JSON 消息体

```

  

### 5.2 通用报文结构

  

```json

{

  "msg_type": "AS_REQ",

  "version": "kerberos-v4-demo",

  "request_id": "uuid-string",

  "timestamp": 1710000000,

  "payload": {}

}

```

  

### 5.3 报文类型

  

| 类型 | 方向 | 说明 |

|---|---|---|

| `AS_REQ` | `Client -> AS` | 请求 `TGT` |

| `AS_REP` | `AS -> Client` | 返回 `TGT` 和 `Kc,tgs` |

| `TGS_REQ` | `Client -> TGS` | 请求服务票据 |

| `TGS_REP` | `TGS -> Client` | 返回 `Service Ticket` 和 `Kc,v` |

| `SERVICE_AUTH_REQ` | `Client -> Service` | 请求进入聊天室 |

| `SERVICE_AUTH_REP` | `Service -> Client` | 双向认证响应 |

| `CHAT_JOIN` | `Client -> Service` | 进入聊天室 |

| `CHAT_MSG` | 双向 | 聊天消息 |

| `CHAT_LEAVE` | `Client -> Service` | 退出聊天室 |

| `ERROR` | 双向 | 错误响应 |

  

### 5.4 错误码设计

  

| 错误码 | 含义 |

|---|---|

| `INVALID_USER` | 用户不存在 |

| `BAD_PASSWORD` | 密码或长期密钥错误 |

| `INVALID_TICKET` | 票据无法解密或格式错误 |

| `EXPIRED_TICKET` | 票据已过期 |

| `TIME_SKEW` | 时间偏差过大 |

| `REPLAY_DETECTED` | 检测到重放请求 |

| `UNKNOWN_SERVICE` | 服务不存在 |

| `DUPLICATE_LOGIN` | 用户重复登录 |

| `AUTH_REQUIRED` | 未认证访问聊天室 |

| `INTERNAL_ERROR` | 服务端内部错误 |

  

## 6. 加密与安全机制设计

  

### 6.1 加密算法

  

系统采用 `DES` 作为对称加密算法，以符合 Kerberos V4 的课程设计要求。实现阶段可调用成熟密码库完成 DES 加解密，项目重点放在 Kerberos 协议流程、票据生成与验证机制上。

  

### 6.2 密钥管理

  

| 密钥 | 保存位置 | 用途 |

|---|---|---|

| `Kc` | SQLite 用户表 | 解密 `AS` 返回给客户端的数据 |

| `Ktgs` | SQLite 或 TGS 配置 | 加密和解密 `TGT` |

| `Kv` | SQLite 服务表 | 加密和解密 `Service Ticket` |

| `Kc,tgs` | 内存 | Client 与 TGS 通信 |

| `Kc,v` | 内存 | Client 与 Service 通信及聊天消息加密 |

  

### 6.3 安全能力

  

| 安全目标 | 实现方式 |

|---|---|

| 用户认证 | `AS` 基于用户长期密钥签发 `TGT` |

| 服务授权 | `TGS` 根据 `TGT` 签发服务票据 |

| 服务端认证 | 服务端返回 `E(Kc,v, TS + 1)` |

| 票据机密性 | 票据使用目标服务长期密钥加密 |

| 抗重放 | 时间戳校验和认证器缓存 |

| 消息保密 | 聊天消息使用 `Kc,v` 加密 |

  

### 6.4 不可否认性说明

  

Kerberos V4 基于对称密钥体系，能够实现双向认证，但不能提供严格意义上的不可否认性。因为通信双方共享会话密钥，第三方无法仅凭密文证明某条消息一定由某一方单独生成。若系统需要不可否认性，应在 Kerberos 认证基础上扩展数字签名机制。本项目不实现数字签名，仅在设计层面说明该限制。

  

## 7. 数据库设计

  

### 7.1 数据库选型

  

系统使用 `SQLite` 保存用户、服务和认证日志。SQLite 部署简单、无需独立数据库服务，适合课程设计和局域网演示。

  

### 7.2 用户表 `users`

  

| 字段名 | 类型 | 约束 | 说明 |

|---|---|---|---|

| `id` | INTEGER | PRIMARY KEY | 用户编号 |

| `username` | TEXT | UNIQUE NOT NULL | 用户名 |

| `derived_key` | TEXT | NOT NULL | 用户长期密钥或密码派生密钥 |

| `client_host` | TEXT | NULL | 绑定或展示用客户端地址 |

| `created_at` | TEXT | NOT NULL | 创建时间 |

  

系统预置四个用户，例如：

  

| 用户名 | 说明 |

|---|---|

| `alice` | 客户端用户 1 |

| `bob` | 客户端用户 2 |

| `carol` | 客户端用户 3 |

| `dave` | 客户端用户 4 |

  

### 7.3 服务表 `services`

  

| 字段名 | 类型 | 约束 | 说明 |

|---|---|---|---|

| `id` | INTEGER | PRIMARY KEY | 服务编号 |

| `service_name` | TEXT | UNIQUE NOT NULL | 服务名称 |

| `service_host` | TEXT | NOT NULL | 服务主机地址 |

| `service_port` | INTEGER | NOT NULL | 服务端口 |

| `service_key` | TEXT | NOT NULL | 服务长期密钥 |

| `created_at` | TEXT | NOT NULL | 创建时间 |

  

### 7.4 认证日志表 `auth_logs`

  

| 字段名 | 类型 | 约束 | 说明 |

|---|---|---|---|

| `id` | INTEGER | PRIMARY KEY | 日志编号 |

| `client_id` | TEXT | NOT NULL | 客户端用户标识 |

| `stage` | TEXT | NOT NULL | 认证阶段 |

| `request_id` | TEXT | NULL | 请求编号 |

| `request_time` | TEXT | NOT NULL | 请求时间 |

| `result` | TEXT | NOT NULL | 成功或失败 |

| `detail` | TEXT | NULL | 详细信息 |

  

`stage` 可取值：

  

- `AS`

- `TGS`

- `SERVICE`

  

### 7.5 文件日志

  

聊天记录和运行日志保存到文件：

  

- `logs/chat.log`：用户进入、退出、发送消息。

- `logs/auth.log`：认证成功、失败和异常访问。

- `logs/debug.log`：开发调试信息。

  

### 7.6 内存状态

  

以下数据仅保存在内存中：

  

- `TGT`

- `Service Ticket`

- `Authenticator`

- 在线用户连接

- 重放检测缓存

- 当前会话密钥

  

## 8. 模块详细设计

  

### 8.1 Client

  

| 子模块 | 职责 |

|---|---|

| 登录模块 | 接收用户名和密码，生成用户长期密钥 |

| AS 通信模块 | 请求并处理 `AS_REP` |

| TGS 通信模块 | 请求并处理 `TGS_REP` |

| 服务认证模块 | 完成 `SERVICE_AUTH_REQ` 和双向认证 |

| 聊天模块 | 加密发送消息、接收并解密消息 |

| GUI 模块 | 展示认证流程、报文、票据和聊天内容 |

  

### 8.2 AS

  

`AS` 的处理流程：

  

1. 接收 `AS_REQ`。

2. 查询用户是否存在。

3. 生成 `Kc,tgs`。

4. 构造并加密 `TGT`。

5. 构造 `AS_REP`。

6. 写入认证日志。

  

### 8.3 TGS

  

`TGS` 的处理流程：

  

1. 接收 `TGS_REQ`。

2. 使用 `Ktgs` 解密 `TGT`。

3. 使用 `Kc,tgs` 解密 `Authenticator`。

4. 校验用户、地址、时间戳和生命周期。

5. 查询目标服务是否存在。

6. 生成 `Kc,v` 和 `Service Ticket`。

7. 写入票据签发日志。

  

### 8.4 Service Server

  

`Service Server` 的处理流程：

  

1. 接收 `SERVICE_AUTH_REQ`。

2. 使用 `Kv` 解密 `Service Ticket`。

3. 使用 `Kc,v` 解密 `Authenticator`。

4. 校验票据有效期和认证器时间戳。

5. 检查重放缓存。

6. 返回双向认证响应。

7. 将认证成功用户加入在线用户表。

8. 接收加密聊天消息并广播。

  

## 9. 聊天室服务设计

  

### 9.1 功能范围

  

聊天室采用单公共房间设计，支持以下功能：

  

- 用户认证成功后进入聊天室。

- 用户发送加密聊天消息。

- 服务端广播消息给在线用户。

- 用户退出聊天室。

- 服务端维护在线用户列表。

  

### 9.2 消息处理流程

  

```text

Client 输入消息

Client 使用 Kc,v 加密消息

Client 发送 CHAT_MSG

Service Server 解密消息

Service Server 写入 chat.log

Service Server 广播消息

Client 接收广播并展示

```

  

### 9.3 重复登录策略

  

系统规定同一用户只保留一个在线会话。实现时建议采用“后登录踢掉旧会话”的策略：

  

- 若用户已在线，新认证会话成功后服务端关闭旧连接。

- 在线用户表更新为最新连接。

- 日志记录重复登录事件。

  

## 10. GUI 设计

  

### 10.1 界面布局

  

客户端 GUI 采用三栏布局：

  

| 区域 | 内容 |

|---|---|

| 左侧认证流程区 | 登录、请求 AS、请求 TGS、连接服务、认证状态 |

| 中间数据细节区 | 报文、票据、认证器、加密前后内容 |

| 右侧聊天室区 | 在线用户、聊天记录、消息输入框、发送按钮 |

  

### 10.2 展示内容

  

GUI 应重点展示：

  

- 当前认证阶段。

- 发送和接收的 JSON 报文。

- `TGT` 和 `Service Ticket` 的字段摘要。

- `Authenticator` 的时间戳和客户端标识。

- 加密前明文、Base64 密文、解密后明文。

- 认证成功或失败原因。

- 在线用户列表和聊天消息。

  

## 11. 部署设计

  

### 11.1 推荐部署

  

| 主机 | 运行程序 | 端口示例 |

|---|---|---:|

| Host-A | `AS` | 8000 |

| Host-B | `TGS` | 8001 |

| Host-C | `Service Server` | 9000 |

| Host-D/E/F/G | `Client` | 客户端主动连接 |

  

如果硬件不足，可以将 `AS` 和 `TGS` 部署在同一主机的不同端口。

  

### 11.2 配置项

  

配置文件应包含：

  

- `AS` 地址和端口。

- `TGS` 地址和端口。

- `Service Server` 地址和端口。

- SQLite 数据库路径。

- 日志文件路径。

- 票据生命周期参数。

- 允许时钟偏差。

  

### 11.3 部署前检查

  

- 所有主机位于同一局域网。

- 防火墙允许对应端口通信。

- 所有主机系统时间误差不超过 120 秒。

- 预置用户和服务密钥已初始化。

- 客户端配置的服务器地址正确。

  

## 12. 测试方案

  

### 12.1 功能测试

  

| 测试项 | 预期结果 |

|---|---|

| 正确用户登录 | 成功获得 `TGT` |

| 请求服务票据 | 成功获得 `Service Ticket` |

| 访问聊天室 | 双向认证成功并进入聊天室 |

| 四用户同时在线 | 四个客户端均可正常收发消息 |

| 加密聊天 | 抓包无法直接看到聊天明文 |

  

### 12.2 异常测试

  

| 测试项 | 预期结果 |

|---|---|

| 错误密码 | `AS` 拒绝认证 |

| 伪造 `TGT` | `TGS` 拒绝请求 |

| 伪造 `Service Ticket` | `Service Server` 拒绝访问 |

| 票据过期 | 系统拒绝继续使用 |

| 时间偏差过大 | 返回 `TIME_SKEW` |

| 重放认证器 | 返回 `REPLAY_DETECTED` |

| 重复登录 | 旧会话被踢下线或新会话被拒绝 |

  

### 12.3 并发测试

  

- 四个客户端同时请求 `AS`。

- 四个客户端同时请求 `TGS`。

- 四个客户端同时进入聊天室。

- 四个客户端连续发送聊天消息。

  

## 13. 小组分工

  

| 成员 | 负责内容 |

|---|---|

| 成员 1 | `Client` 认证通信逻辑、票据保存、服务访问流程 |

| 成员 2 | `AS` 和 `TGS`、票据生成、会话密钥生成、数据库查询 |

| 成员 3 | `Service Server`、双向认证、聊天室广播、在线用户管理 |

| 成员 4 | GUI、日志展示、数据库初始化、系统集成测试 |

  

## 14. 风险与应对

  

| 风险 | 影响 | 应对措施 |

|---|---|---|

| 多主机时间不同步 | 认证失败 | 演示前统一校时，允许 120 秒偏差 |

| TCP 粘包和半包 | 报文解析失败 | 使用长度前缀封包 |

| DES 调试复杂 | 加解密失败 | 优先调用成熟库，统一封装加密接口 |

| GUI 与网络阻塞 | 界面卡顿 | 网络通信放入线程或异步任务 |

| 多人并行开发冲突 | 集成困难 | 先固定公共协议和数据结构 |

| 重复登录状态混乱 | 在线用户错误 | 服务端统一维护在线会话表 |

  

## 15. 总结

  

本项目设计了一个基于 Kerberos V4 的局域网认证聊天室系统。系统通过 `AS`、`TGS` 和 `Service Server` 的分层设计，实现了票据签发、服务授权、双向认证、会话密钥分发和加密聊天等功能。客户端图形界面用于展示认证过程中的报文、票据和加解密数据，使系统既具备真实运行能力，也适合网络安全课程的课堂演示和答辩说明。

  

后续实现阶段应优先完成公共协议结构、加密封装、SQLite 初始化和三阶段认证闭环，再逐步完善 GUI 展示、聊天室广播和异常测试。