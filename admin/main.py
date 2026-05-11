"""管理端程序入口。"""

from __future__ import annotations

import sys

from PyQt5.QtWidgets import QApplication

from admin.ui import AdminConsole


def main() -> None:
    """启动 SafeChat 管理控制台。"""
    app = QApplication(sys.argv)
    window = AdminConsole()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
