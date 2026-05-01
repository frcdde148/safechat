"""Shared PyQt5 style sheet for the SafeChat client."""


APP_STYLE = """
QWidget {
    background: #f6f7f9;
    color: #1f2933;
    font-family: "Microsoft YaHei", "Segoe UI", sans-serif;
    font-size: 26px;
}

QLineEdit, QTextEdit, QListWidget, QComboBox, QSpinBox {
    background: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: 12px;
}

QLineEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus {
    border-color: #2563eb;
}

QPushButton {
    background: #2563eb;
    color: #ffffff;
    border: none;
    border-radius: 6px;
    padding: 14px 24px;
    font-weight: 600;
}

QPushButton:hover {
    background: #1d4ed8;
}

QPushButton:disabled {
    background: #94a3b8;
}

QPushButton#secondaryButton {
    background: #e2e8f0;
    color: #1e293b;
}

QPushButton#secondaryButton:hover {
    background: #cbd5e1;
}

QPushButton#secondaryButton:disabled {
    background: #e2e8f0;
    color: #94a3b8;
}

QFrame#panel {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
}

QLabel#title {
    color: #0f172a;
    font-size: 40px;
    font-weight: 700;
}

QLabel#sectionTitle {
    color: #334155;
    font-weight: 700;
}

QLabel#hint {
    color: #64748b;
}

QLabel#okBadge {
    background: #dcfce7;
    color: #166534;
    border-radius: 6px;
    padding: 8px 14px;
}

QLabel#warnBadge {
    background: #ffedd5;
    color: #9a3412;
    border-radius: 6px;
    padding: 8px 14px;
}

QLabel#errorBadge {
    background: #fee2e2;
    color: #991b1b;
    border-radius: 6px;
    padding: 8px 14px;
}

QLabel#mutedBadge {
    background: #e2e8f0;
    color: #475569;
    border-radius: 6px;
    padding: 8px 14px;
}
"""
