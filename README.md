# 网络安全课程设计

本项目是一个基于 Kerberos V4 的局域网认证聊天室系统，包含 `Client`、`AS`、`TGS`、`Service Server` 四类实体，并通过 `PyQt/PySide` GUI 展示认证与报文细节。

## 项目目录

```text
.
├── README.md
├── doc.md
├── as_server/
│   ├── __init__.py
│   ├── main.py
│   └── README.md
├── client/
│   ├── __init__.py
│   ├── main.py
│   ├── README.md
│   └── gui/
│       ├── __init__.py
│       └── README.md
├── common/
│   ├── __init__.py
│   ├── config.py
│   ├── crypto.py
│   ├── database.py
│   ├── logger.py
│   ├── models.py
│   ├── protocol.py
│   └── utils.py
├── config/
│   ├── README.md
│   └── settings.example.json
├── data/
│   ├── .gitkeep
│   └── README.md
├── logs/
│   ├── .gitkeep
│   └── README.md
├── scripts/
│   ├── README.md
│   └── init_db.py
├── service_server/
│   ├── __init__.py
│   ├── main.py
│   └── README.md
├── tests/
│   ├── __init__.py
│   └── README.md
└── tgs_server/
    ├── __init__.py
    ├── main.py
    └── README.md
```

## 目录说明

- `client/`：客户端程序与 GUI 逻辑。
- `as_server/`：认证服务器程序。
- `tgs_server/`：票据授权服务器程序。
- `service_server/`：聊天室服务端程序。
- `common/`：共享的数据结构、协议封装、加密、配置和日志工具。
- `config/`：配置模板与部署配置文件。
- `data/`：SQLite 数据库等运行时数据。
- `logs/`：认证日志和聊天日志。
- `scripts/`：初始化数据库等辅助脚本。
- `tests/`：测试代码。

