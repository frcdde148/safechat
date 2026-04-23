"""Client entry point."""

from __future__ import annotations

import sys

from PyQt5.QtWidgets import QApplication

from client.ui.main_window import MainWindow


def main() -> None:
    """Start the client application."""
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
