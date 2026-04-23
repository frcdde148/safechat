"""Authentication phase status widgets."""

from __future__ import annotations

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QFrame, QGridLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget


AUTH_STAGES = (
    ("C_AS_REQ", "步骤1 请求 TGT"),
    ("AS_C_REP", "步骤2 返回 TGT"),
    ("C_TGS_REQ", "步骤3 请求服务票据"),
    ("TGS_C_REP", "步骤4 返回服务票据"),
    ("C_V_REQ", "步骤5 请求聊天室"),
    ("V_C_REP", "步骤6 双向认证"),
)


class StageRow(QFrame):
    """Single Kerberos authentication stage row."""

    def __init__(self, code: str, label: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("stageRow")
        self.code_label = QLabel(code)
        self.code_label.setMinimumWidth(92)
        self.code_label.setStyleSheet("font-weight: 700; color: #1e293b;")

        self.text_label = QLabel(label)
        self.text_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        self.status_label = QLabel("等待")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setObjectName("mutedBadge")
        self.status_label.setMinimumWidth(58)

        layout = QGridLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setHorizontalSpacing(8)
        layout.addWidget(self.code_label, 0, 0)
        layout.addWidget(self.text_label, 0, 1)
        layout.addWidget(self.status_label, 0, 2)

    def set_status(self, status: str) -> None:
        """Set visual status for this stage."""
        status_map = {
            "waiting": ("等待", "mutedBadge"),
            "running": ("进行中", "warnBadge"),
            "success": ("成功", "okBadge"),
            "failed": ("失败", "errorBadge"),
        }
        text, object_name = status_map.get(status, status_map["waiting"])
        self.status_label.setText(text)
        self.status_label.setObjectName(object_name)
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)


class AuthFlowView(QFrame):
    """Display Kerberos six-step authentication progress."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("panel")
        self.stage_rows: dict[str, StageRow] = {}

        title = QLabel("认证阶段")
        title.setObjectName("sectionTitle")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)
        layout.addWidget(title)

        for code, label in AUTH_STAGES:
            row = StageRow(code, label)
            self.stage_rows[code] = row
            layout.addWidget(row)

        layout.addStretch(1)

    def reset(self) -> None:
        """Reset all stages to waiting."""
        for row in self.stage_rows.values():
            row.set_status("waiting")

    def mark_running(self, stage_code: str) -> None:
        """Mark a stage as running."""
        self.stage_rows[stage_code].set_status("running")

    def mark_success(self, stage_code: str) -> None:
        """Mark a stage as successful."""
        self.stage_rows[stage_code].set_status("success")

    def mark_failed(self, stage_code: str) -> None:
        """Mark a stage as failed."""
        self.stage_rows[stage_code].set_status("failed")
