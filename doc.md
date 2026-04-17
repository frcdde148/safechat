基于 Kerberos V4 的局域网认证聊天室系统设计文档
1. 绪论
1.1 项目背景
随着网络应用的普及，用户身份认证已成为网络安全中的核心问题。传统基于口令的认证方式存在密码明文传输、重复登录验证繁琐、安全性不足等问题。Kerberos 是一种经典的基于对称密钥和票据机制的身份认证协议，能够在不直接传输用户密码的前提下完成安全认证，并支持单点登录思想。

本课程设计以 Kerberos V4 为基础，在局域网多主机环境下实现一个真实可运行的认证系统，并以受保护聊天室作为服务场景，使认证成功的用户才能进入聊天室进行通信。系统通过图形界面展示认证过程中的报文、票据和加解密细节，以便更直观地理解 Kerberos V4 的工作机制。

1.2 项目目标
本项目的目标是在局域网环境下实现一个严格遵循 Kerberos V4 核心流程的认证系统，完成以下内容：

实现 Client、AS、TGS、Service Server 四类实体
实现 Client-AS、Client-TGS、Client-Service 三阶段认证流程
实现基于 Kerberos V4 的双向认证机制
实现受 Kerberos 保护的聊天室服务
实现聊天消息的加密传输
通过 GUI 展示认证各阶段的数据细节
支持四个预置用户分别从四台主机访问同一服务
1.3 项目定位
本系统面向教学演示，重点在于协议流程的正确实现、系统的可运行性以及界面的展示效果，不追求工业级高可用、跨域认证和复杂服务扩展能力。

2. 需求分析
2.1 功能需求
系统应满足以下功能需求：

用户输入用户名和密码后发起登录认证
客户端向 AS 请求票据授权票据 TGT
AS 验证用户后返回 TGT 和 Client-TGS Session Key
客户端向 TGS 请求聊天室服务票据
TGS 验证后返回 Service Ticket 和 Client-Service Session Key
客户端向 Service Server 提交服务票据和认证器完成认证
服务端完成双向认证后允许客户端进入聊天室
聊天室支持在线用户发送和接收广播消息
聊天消息使用会话密钥加密传输
GUI 可展示报文结构、票据内容、时间戳、生命周期、加解密结果
服务端保存聊天记录到日志文件
同一用户只保留一个在线会话，重复登录时旧会话失效或被拒绝
2.2 非功能需求
系统应满足以下非功能需求：

运行环境为局域网多主机环境
四台主机各运行一个 Client
认证协议基于 TCP Socket 实现
客户端采用 PyQt/PySide 构建图形界面
系统严格遵循 Kerberos V4 核心认证流程
系统具备基本时间戳校验和重放攻击防护能力
系统部署和运行方式应简单，适合课程设计快速开发与演示
2.3 约束条件
预置四个用户，不实现注册功能
不实现跨 Realm 认证
不专门实现断线重连机制，掉线后需重新认证
不实现多聊天室、多房间、私聊、文件传输等扩展功能
不要求工业级性能优化和高可用部署
3. 系统总体设计
3.1 系统组成
系统由以下四类实体组成：

Client
负责用户登录、请求票据、访问服务、发送聊天消息和展示认证过程
AS（Authentication Server）
负责验证用户身份并签发 TGT
TGS（Ticket Granting Server）
负责验证 TGT 并签发 Service Ticket
Service Server
负责验证服务票据、完成双向认证，并提供聊天室服务
3.2 服务场景
本系统将 Service Server 设计为受 Kerberos V4 保护的公共聊天室。只有完成完整认证流程并通过服务端验证的客户端，才允许进入聊天室进行消息收发。

聊天室采用单服务实例、单公共房间的设计，所有认证成功的用户进入同一聊天空间。聊天室仅提供最基本的进入、广播聊天、接收消息和退出功能。

3.3 总体流程
系统总体流程如下：

用户在客户端输入用户名和密码
客户端向 AS 发起认证请求
AS 返回 TGT 和 Client-TGS Session Key
客户端使用 TGT 向 TGS 申请聊天室服务票据
TGS 返回 Service Ticket 和 Client-Service Session Key
客户端持 Service Ticket 向 Service Server 发起认证
Service Server 完成双向认证后允许客户端接入聊天室
客户端使用 Client-Service Session Key 加密聊天消息并进行通信
4. Kerberos V4 协议流程设计
4.1 协议角色
Kerberos V4 中涉及以下角色：

Client：请求访问服务的用户端
AS：认证服务器，验证用户身份
TGS：票据授权服务器，签发具体服务票据
Service Server：提供实际服务的服务器
4.2 核心对象
系统实现以下 Kerberos V4 核心对象：

TGT
由 AS 签发，供客户端向 TGS 证明身份
Service Ticket
由 TGS 签发，供客户端向服务端证明身份
Authenticator
由客户端生成，证明请求者是票据合法持有者
Client-TGS Session Key
用于客户端与 TGS 安全通信
Client-Service Session Key
用于客户端与服务端安全通信及聊天消息加密
4.3 认证流程
4.3.1 Client 与 AS 认证
客户端向 AS 发送认证请求，请求内容包括：

客户端标识 IDc
票据授权服务器标识 IDtgs
时间戳 TS1
AS 验证用户合法性后，生成 Client-TGS Session Key，并返回：

使用用户长期密钥加密的响应内容
TGT
其中：

返回给客户端的敏感部分用用户长期密钥加密
TGT 用 TGS 长期密钥加密
4.3.2 Client 与 TGS 认证
客户端向 TGS 发送服务票据请求，请求内容包括：

服务端标识 IDv
TGT
Authenticator_c
其中 Authenticator_c 使用 Client-TGS Session Key 加密。

TGS 验证通过后，返回：

使用 Client-TGS Session Key 加密的响应内容
Service Ticket
其中：

返回给客户端的敏感部分用 Client-TGS Session Key 加密
Service Ticket 用 Service Server 长期密钥加密
4.3.3 Client 与 Service Server 认证
客户端向服务端发送：

Service Ticket
Authenticator_c
其中 Authenticator_c 使用 Client-Service Session Key 加密。

Service Server 解密票据并验证认证器后，返回：

timestamp + 1 的加密确认信息
客户端解密验证成功后，说明服务端身份可信，双向认证完成，允许进入聊天室。

4.4 时间机制
为保证协议安全性，系统采用时间戳和生命周期机制：

允许时钟偏差：120 秒
TGT 有效期：5 分钟
Service Ticket 有效期：3 分钟
Authenticator 有效期：1 分钟
若时间戳超出允许范围，系统拒绝认证请求。

4.5 重放攻击防护
系统在 Service Server 中实现简化的重放攻击防护机制：

缓存最近已使用的 client_id + timestamp
若相同认证器在有效时间窗内重复出现，则判定为重放攻击并拒绝请求
5. 系统模块设计
5.1 Client 模块设计
客户端模块包括以下子模块：

5.1.1 用户登录模块
负责接收用户输入的用户名和密码，并发起初始认证请求。

5.1.2 密钥生成模块
根据用户输入的密码生成用户长期密钥，用于解密 AS 返回的数据。

5.1.3 AS 通信模块
负责向 AS 发送认证请求并接收响应，提取 Client-TGS Session Key 和 TGT。

5.1.4 TGS 通信模块
负责构造 Authenticator，向 TGS 申请聊天室服务票据，并接收 Client-Service Session Key 和 Service Ticket。

5.1.5 Service 认证模块
负责向 Service Server 提交服务票据和认证器，完成双向认证。

5.1.6 聊天模块
负责在认证成功后建立聊天连接，使用 Client-Service Session Key 对聊天消息进行加密和解密。

5.1.7 GUI 展示模块
负责展示以下内容：

认证流程步骤
发送和接收的报文
TGT 和 Service Ticket 的字段内容
加密前数据、加密后密文、解密后结果
认证成功或失败原因
聊天消息和在线用户列表
5.2 AS 模块设计
AS 模块包括：

用户信息查询
用户身份验证
Client-TGS Session Key 生成
TGT 生成
报文加密与响应封装
认证日志记录
5.3 TGS 模块设计
TGS 模块包括：

TGT 解密
Authenticator 校验
服务合法性检查
Client-Service Session Key 生成
Service Ticket 生成
报文加密与响应封装
票据签发日志记录
5.4 Service Server 模块设计
Service Server 模块包括：

Service Ticket 解密
Authenticator 校验
双向认证确认
在线用户管理
聊天消息接收与广播
重放缓存管理
聊天日志和访问日志记录
5.5 数据存储模块设计
数据存储模块负责：

用户信息维护
服务信息维护
密钥信息维护
认证日志持久化
聊天记录日志保存
6. 数据库设计
6.1 数据库选型
本系统采用 SQLite 作为持久化存储方案。其优点是：

部署简单
无需额外数据库服务器
适合课程设计项目
易于调试和演示
6.2 用户表 users
用于保存预置用户信息。

字段名	类型	含义
id	INTEGER	主键
username	TEXT	用户名
derived_key	TEXT	用户长期密钥或密码派生密钥
client_host	TEXT	客户端主机标识
created_at	TEXT	创建时间
说明：系统预置四个用户，不提供注册接口。

6.3 服务表 services
用于保存服务端信息。

字段名	类型	含义
id	INTEGER	主键
service_name	TEXT	服务名称
service_host	TEXT	服务主机地址
service_port	INTEGER	服务端口
service_key	TEXT	服务长期密钥
created_at	TEXT	创建时间
6.4 认证日志表 auth_logs
用于记录认证过程。

字段名	类型	含义
id	INTEGER	主键
client_id	TEXT	客户端标识
stage	TEXT	认证阶段
request_time	TEXT	请求时间
result	TEXT	成功或失败
detail	TEXT	详细说明
其中 stage 包括：

AS
TGS
SERVICE
6.5 聊天日志
聊天室消息不写入数据库，保存到日志文件中。这样实现更简单，也更符合课程设计快速开发的目标。

6.6 内存中保存的数据
以下数据仅保存在内存中：

TGT
Service Ticket
Authenticator
在线用户状态
重放攻击缓存
当前会话密钥
这类数据生命周期短，存储于内存更符合 Kerberos 票据的使用语义。

7. 通信与报文设计
7.1 通信方式
系统采用 TCP Socket 作为底层通信方式。原因如下：

更贴近 Kerberos 协议报文交换本质
便于自定义报文格式
有利于展示认证过程
实现复杂度适中，适合 Python 开发
7.2 报文格式
系统统一使用：

明文结构：JSON
密文字段：加密后使用 Base64 编码
传输方式：基于 TCP Socket 发送 JSON 字符串
7.3 报文字段设计原则
每类报文包含消息类型字段，便于识别
票据和认证器分开表示
所有加密内容明确标记加密方式和字段范围
时间戳、生命周期、客户端标识和服务标识为必要字段
7.4 典型报文内容
7.4.1 AS 请求报文
包含以下字段：

msg_type
client_id
tgs_id
timestamp
7.4.2 AS 响应报文
包含以下字段：

msg_type
encrypted_data
tgt
7.4.3 TGS 请求报文
包含以下字段：

msg_type
service_id
tgt
authenticator
7.4.4 TGS 响应报文
包含以下字段：

msg_type
encrypted_data
service_ticket
7.4.5 Service 认证请求报文
包含以下字段：

msg_type
service_ticket
authenticator
7.4.6 Service 认证响应报文
包含以下字段：

msg_type
mutual_auth_data
7.4.7 聊天消息报文
包含以下字段：

msg_type
sender
cipher_text
timestamp
8. 加密与安全机制设计
8.1 加密算法
系统采用 DES 作为对称加密算法，以符合 Kerberos V4 的协议要求。实现时可调用成熟加密库，以保证正确性和开发效率。

8.2 密钥类型
系统中涉及以下密钥：

用户长期密钥
TGS 长期密钥
服务端长期密钥
Client-TGS Session Key
Client-Service Session Key
8.3 加密策略
AS 返回给客户端的敏感数据使用用户长期密钥加密
TGT 使用 TGS 长期密钥加密
TGS 返回给客户端的敏感数据使用 Client-TGS Session Key 加密
Service Ticket 使用服务端长期密钥加密
服务端双向认证确认信息使用 Client-Service Session Key 加密
聊天消息使用 Client-Service Session Key 加密
8.4 双向认证机制
系统严格实现双向认证机制：

客户端向服务端发送 Service Ticket 和 Authenticator
服务端验证成功后返回加密的 timestamp + 1
客户端验证成功后确认服务端身份可信
8.5 重复登录控制
系统规定同一用户名只保留一个在线会话：

当同一用户再次登录时，旧会话应被踢下线或新会话被拒绝
实现时可选择服务端主动断开旧连接，或直接拒绝新的连接请求
8.6 重放攻击防护
服务端维护短时间认证器缓存，若同一用户在有效时间窗口内重复提交相同认证信息，则拒绝访问。

9. 聊天室服务设计
9.1 功能范围
聊天室功能限定为：

用户进入公共聊天室
用户发送消息
其他在线用户接收广播消息
用户退出聊天室
9.2 功能限制
为了突出认证主题，本系统不实现以下功能：

私聊
多房间
离线消息
文件传输
历史消息数据库持久化
断线自动重连
9.3 消息加密
聊天消息在客户端使用 Client-Service Session Key 加密后发送至服务端。服务端解密后可选择重新封装并广播给其他客户端，保证聊天内容在传输过程中不以明文暴露。

9.4 在线用户管理
服务端维护当前在线用户列表，只有已通过认证的客户端才可加入在线列表。用户掉线或退出后从列表中移除。

9.5 聊天日志
服务端将以下内容写入日志文件：

用户进入聊天室时间
用户退出聊天室时间
用户发送的消息
非法访问与异常认证记录
10. 图形界面设计
10.1 界面框架
客户端使用 PyQt/PySide 实现桌面图形界面。界面分为三个主要区域：

左侧：认证流程区
中间：数据细节展示区
右侧：聊天室区
10.2 认证流程区
该区域显示：

用户名输入框
密码输入框
请求 AS 按钮
请求 TGS 按钮
连接服务按钮
当前认证阶段和结果
10.3 数据细节展示区
该区域用于展示认证的核心细节，包括：

当前请求报文
当前响应报文
加密前内容
Base64 密文
解密后内容
TGT 字段信息
Service Ticket 字段信息
Authenticator 字段信息
时间戳与生命周期说明
错误原因说明
10.4 聊天室区
该区域显示：

在线用户列表
聊天消息窗口
输入框
发送按钮
10.5 界面目标
图形界面的主要目标是增强演示效果，使系统不仅能运行，还能直观展示 Kerberos V4 的完整认证过程和数据变化。

11. 系统部署设计
11.1 部署方式
系统运行于局域网多主机环境，部署方案如下：

一台主机运行 AS
一台主机运行 TGS
一台主机运行 Service Server
四台主机分别运行 Client
若硬件资源不足，可将 AS 与 TGS 部署在同一主机的不同端口上。

11.2 网络要求
部署前应保证：

所有主机位于同一局域网
主机间网络连通
各实体使用固定 IP 和端口
所有主机系统时间尽量一致
11.3 时间同步要求
由于 Kerberos 依赖时间戳，系统要求所有主机时间同步，允许误差不超过 120 秒。若误差过大，将导致认证失败。

12. 测试方案
12.1 功能测试
正确用户名和密码可成功获取 TGT
持有合法 TGT 可成功获取 Service Ticket
持有合法服务票据可成功进入聊天室
四个客户端可同时在线聊天
聊天消息可成功加密、解密和广播
12.2 异常测试
错误密码导致登录失败
伪造 TGT 被 TGS 拒绝
伪造 Service Ticket 被服务端拒绝
票据过期后访问失败
时间戳超出允许偏差后认证失败
重放旧认证器被服务端拒绝
同一用户重复登录时旧会话被替换或新会话被拒绝
12.3 安全测试
未认证用户不能进入聊天室
篡改密文后不能正常通过认证
双向认证失败时不能访问聊天室
聊天消息抓包后无法直接读取明文内容
12.4 并发测试
四个客户端同时认证
四个客户端同时发送消息
服务端可正确维护在线用户列表和广播逻辑
13. 小组分工建议
成员 1
负责 Client 认证通信逻辑，包括：

用户登录流程
AS 请求与响应处理
TGS 请求与响应处理
Service 认证请求处理
成员 2
负责 AS 与 TGS 模块，包括：

用户验证
TGT 生成与解析
Service Ticket 生成与解析
会话密钥生成
协议字段封装
成员 3
负责 Service Server 与聊天室模块，包括：

服务票据验证
双向认证
在线用户管理
消息广播
聊天日志记录
成员 4
负责 GUI 与系统集成，包括：

PyQt/PySide 图形界面
报文和票据展示
数据库存储
日志展示
联调与测试支持
14. 总结与展望
本项目设计了一个基于 Kerberos V4 的局域网认证聊天室系统。系统严格遵循 Kerberos V4 的核心认证流程，实现了 Client、AS、TGS 和 Service Server 四类实体，并将聊天室作为受保护服务场景。通过使用票据机制、时间戳校验、双向认证和消息加密，系统能够较完整地展示 Kerberos V4 的工作原理。

本系统适用于课程设计和教学演示，重点在于协议流程的实现与可视化展示。未来若进一步扩展，可考虑增加跨域认证、多服务接入、自动时间同步、历史消息持久化和更完善的异常恢复机制。