"""认证阶段状态控件。用于显示各认证阶段的可视化状态和报文详情。"""

from __future__ import annotations

import json

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QFrame, QGridLayout, QLabel, QSizePolicy, QTextEdit, QVBoxLayout, QWidget


AUTH_STAGES = (
    ("C_AS_REQ", "步骤1 Client请求 TGT"),
    ("AS_C_REP", "步骤2 AS返回 TGT"),
    ("C_TGS_REQ", "步骤3 Client请求 Service Ticket"),
    ("TGS_C_REP", "步骤4 TGS返回 Service Ticket"),
    ("C_V_REQ", "步骤5 Client请求服务"),
    ("V_C_REP", "步骤6 Client/Server 相互认证"),
)


class StageRow(QFrame):
    """单个 Kerberos 认证阶段的行视图。

    每一行展示阶段编码、阶段描述以及当前状态。
    """

    clicked = pyqtSignal(str)

    def __init__(self, code: str, label: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.code = code
        self._selected = False
        self.setObjectName("stageRow")
        self.setCursor(Qt.PointingHandCursor)
        self.code_label = QLabel(code)
        self.code_label.setMinimumWidth(170)
        self.code_label.setStyleSheet("font-weight: 700; color: #1e293b;")

        self.text_label = QLabel(label)
        self.text_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

        self.status_label = QLabel("等待")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setObjectName("mutedBadge")
        self.status_label.setMinimumWidth(110)

        layout = QGridLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setHorizontalSpacing(8)
        layout.addWidget(self.code_label, 0, 0)
        layout.addWidget(self.text_label, 0, 1)
        layout.addWidget(self.status_label, 0, 2)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self.code)
        super().mousePressEvent(event)

    def set_status(self, status: str) -> None:
        """设置该阶段的可视化状态。

        参数 `status` 使用内部标识："waiting", "running", "success", "failed"。
        会更新行内显示文本和对应的样式对象名，从而改变视觉样式。
        """
        # 状态映射：内部状态 -> (显示文本, 样式对象名)
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

    def set_selected(self, selected: bool) -> None:
        self._selected = selected
        if selected:
            self.setStyleSheet("QFrame#stageRow { background: #eef2ff; border: 1px solid #6366f1; border-radius: 8px; }")
        else:
            self.setStyleSheet("QFrame#stageRow { background: transparent; border: none; }")


class AuthFlowView(QFrame):
    """显示 Kerberos 六步认证进度的视图。

    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("panel")
        self.stage_rows: dict[str, StageRow] = {}
        self.stage_details: dict[str, dict[str, object]] = {}
        self._current_stage_code: str | None = None
        self.cipher_view = QTextEdit()
        self.cipher_view.setReadOnly(True)
        self.cipher_view.setPlaceholderText("这里显示密文、发送报文和协议主体。")
        self.plain_view = QTextEdit()
        self.plain_view.setReadOnly(True)
        self.plain_view.setPlaceholderText("这里显示对应的明文、结构说明和客户端保存内容。")

        title = QLabel("认证阶段")
        title.setObjectName("sectionTitle")
        detail_title = QLabel("报文细节")
        detail_title.setObjectName("sectionTitle")
        cipher_title = QLabel("网络传输报文")
        cipher_title.setObjectName("sectionTitle")
        plain_title = QLabel("客户端解密结果")
        plain_title.setObjectName("sectionTitle")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)
        layout.addWidget(title)

        for code, label in AUTH_STAGES:
            row = StageRow(code, label)
            row.clicked.connect(self.show_stage_detail)
            self.stage_rows[code] = row
            layout.addWidget(row)

        layout.addWidget(detail_title)
        detail_grid = QGridLayout()
        detail_grid.setHorizontalSpacing(12)
        detail_grid.setVerticalSpacing(8)
        detail_grid.addWidget(cipher_title, 0, 0)
        detail_grid.addWidget(plain_title, 0, 1)
        detail_grid.addWidget(self.cipher_view, 1, 0)
        detail_grid.addWidget(self.plain_view, 1, 1)
        layout.addLayout(detail_grid, 1)

    def reset(self) -> None:
        self.stage_details = {}
        self._current_stage_code = None
        for row in self.stage_rows.values():
            row.set_status("waiting")
            row.set_selected(False)
        self.cipher_view.clear()
        self.plain_view.clear()

    def mark_running(self, stage_code: str) -> None:
        self.stage_rows[stage_code].set_status("running")

    def mark_success(self, stage_code: str) -> None:
    
        self.stage_rows[stage_code].set_status("success")

    def mark_failed(self, stage_code: str) -> None:
        self.stage_rows[stage_code].set_status("failed")

    def append_detail(self, stage_code: str, title: str, body: str) -> None:
        self.stage_details[stage_code] = {"title": title, "body": body}
        self.show_stage_detail(stage_code)

    def append_message(self, title: str, body: str) -> None:
        """在详情区显示一条非阶段性的信息，不会缓存为阶段条目。"""
        title = str(title)
        body = str(body)
        cipher_html, plain_html = self._render_detail(body)
        self.cipher_view.setHtml(self._wrap_html(f"<h3>{self._escape_html(title)}</h3>{cipher_html}", "#fff7ed", "#9a3412"))
        self.plain_view.setHtml(self._wrap_html(f"<h3>{self._escape_html(title)}</h3>{plain_html}", "#eff6ff", "#1d4ed8"))

    def show_stage_detail(self, stage_code: str) -> None:
        detail = self.stage_details.get(stage_code)
        if not detail:
            return

        self._current_stage_code = stage_code
        for code, row in self.stage_rows.items():
            row.set_selected(code == stage_code)

        title = str(detail.get("title", stage_code))
        body = str(detail.get("body", ""))
        cipher_html, plain_html = self._render_detail(body)
        self.cipher_view.setHtml(self._wrap_html(f"<h3>{self._escape_html(title)}</h3>{cipher_html}", "#fff7ed", "#9a3412"))
        self.plain_view.setHtml(self._wrap_html(f"<h3>{self._escape_html(title)}</h3>{plain_html}", "#eff6ff", "#1d4ed8"))

    @staticmethod
    def _render_detail(body: str) -> tuple[str, str]:
        try:
            payload = json.loads(body)
        except Exception:
            safe_body = AuthFlowView._escape_html(body)
            return (f"<pre>{safe_body}</pre>", "<pre>无可解析的明文结构</pre>")

        cipher_parts: list[str] = []
        plain_parts: list[str] = []
        formula = payload.get("公式")
        if formula:
            cipher_parts.append(f"<p><b>公式</b>：{AuthFlowView._escape_html(str(formula))}</p>")

        send_value = payload.get("send")
        receive_value = payload.get("receive")
        if send_value is not None:
            cipher_parts.append(AuthFlowView._format_section("send", send_value, "#b45309"))
        if receive_value is not None:
            cipher_parts.append(AuthFlowView._format_section("receive", receive_value, "#b45309"))

        for key in ("plaintext", "authenticator_structure", "client_saved", "authenticated"):
            if key in payload:
                plain_parts.append(AuthFlowView._format_section(key, payload[key], "#2563eb" if key != "authenticated" else "#059669"))

        if not cipher_parts:
            cipher_parts.append("<pre>无密文内容</pre>")
        if not plain_parts:
            plain_parts.append("<pre>尚无需要客户端解密的内容</pre>")

        return "".join(cipher_parts), "".join(plain_parts)

    @staticmethod
    def _format_section(name: str, value: object, color: str) -> str:
        rendered = AuthFlowView._render_json_value(value)
        return (
            f'<div style="margin-bottom: 12px;">'
            f'<div style="color: {color}; font-weight: 700; margin-bottom: 4px;">{AuthFlowView._escape_html(name)}</div>'
            f'{rendered}'
            f'</div>'
        )

    @staticmethod
    def _render_json_value(value: object) -> str:
        if isinstance(value, (dict, list)):
            text = json.dumps(value, ensure_ascii=False, indent=2)
        else:
            text = json.dumps(value, ensure_ascii=False)
        return f"<pre>{AuthFlowView._highlight_protocol_terms(AuthFlowView._escape_html(text))}</pre>"

    @staticmethod
    def _wrap_html(content: str, background: str, border_color: str) -> str:
        return (
            f'<div style="background: {background}; border: 1px solid {border_color}; border-radius: 8px; padding: 12px;">'
            f'{content}'
            f'</div>'
        )

    @staticmethod
    def _escape_html(text: str) -> str:
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    @staticmethod
    def _highlight_protocol_terms(text: str) -> str:
        """高亮 Kerberos 协议中常见的字段名和密钥名。"""
        import re

        highlight_rules = [
            (r"\b(id_c|id_tgs|id_v|id_t)\b", "#1d4ed8"),
            (r"\b(k_c_tgs|k_c_v|k_c)\b", "#7c3aed"),
            (r"\b(ticket_tgs|ticket_v|tgt)\b", "#b45309"),
            (r"\b(authenticator_c|authenticator_structure)\b", "#0f766e"),
            (r"\b(ts_\d+(?:_plus_\d+)?)\b", "#be185d"),
            (r"\b(lifetime_\d+)\b", "#b45309"),
            (r"\b(client_saved|plaintext|receive|send|extensions|authenticated)\b", "#475569"),
        ]

        def replace(match: re.Match[str], color: str) -> str:
            value = match.group(0)
            return f'<span style="font-weight: 700; color: {color};">{value}</span>'

        highlighted = text
        for pattern, color in highlight_rules:
            highlighted = re.sub(pattern, lambda match: replace(match, color), highlighted)
        return highlighted
