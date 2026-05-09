"""Admin console entry point."""

from __future__ import annotations

import sys

from PyQt5.QtWidgets import QApplication

from admin.ui import AdminConsole


def main() -> None:
    """Start the SafeChat admin console."""
    app = QApplication(sys.argv)
    window = AdminConsole()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
