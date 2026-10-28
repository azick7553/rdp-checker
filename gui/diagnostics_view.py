"""Вкладка «Диагностика»: что доступно мониторингу под текущей учётной записью."""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget

from core import winapi
from core.diagnostics import DiagnosticItem, diagnostics_report
from gui.widgets import Card, Chip, SectionTitle, page_header


class DiagnosticsView(QScrollArea):
    rerun_requested = Signal()

    def __init__(self, data_dir: str, log_path: str, parent=None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        body = QWidget()
        self.setWidget(body)
        lay = QVBoxLayout(body)
        lay.setContentsMargins(28, 22, 28, 22)
        lay.setSpacing(12)
        lay.addWidget(page_header("Диагностика",
                                  "Какие источники данных Windows доступны монитору под вашей учётной записью. "
                                  "Приложение не пытается обходить ограничения Windows."))
        bar = QHBoxLayout()
        self.b_run = QPushButton("Проверить снова")
        self.b_run.setObjectName("Primary")
        self.b_copy = QPushButton("Копировать диагностическую информацию")
        self.copied = QLabel("")
        self.copied.setObjectName("Muted")
        bar.addWidget(self.b_run)
        bar.addWidget(self.b_copy)
        bar.addWidget(self.copied)
        bar.addStretch(1)
        lay.addLayout(bar)

        info = winapi.system_info()
        sys_card = Card()
        sys_card.lay.addWidget(SectionTitle("Система"))
        for k, v in (("Компьютер", info["computer"]),
                     ("Пользователь", f"{info['domain']}\\{info['user']}" if info.get("domain") else info["user"]),
                     ("Windows", f"{info['os']} — {info['os_version']}"),
                     ("Данные приложения", data_dir), ("Журнал ошибок", log_path)):
            row = QLabel(f"<span style='color:#9d9d9d'>{k}:</span>&nbsp; {v}")
            row.setTextFormat(Qt.RichText)
            row.setTextInteractionFlags(Qt.TextSelectableByMouse)
            row.setWordWrap(True)
            sys_card.lay.addWidget(row)
        lay.addWidget(sys_card)

        self.status = QLabel("Проверка выполняется…")
        self.status.setObjectName("Muted")
        lay.addWidget(self.status)
        self.box = QVBoxLayout()
        self.box.setSpacing(8)
        lay.addLayout(self.box)
        lay.addStretch(1)
        self._items: list[DiagnosticItem] = []
        self.b_run.clicked.connect(self._rerun)
        self.b_copy.clicked.connect(self._copy)

    def _rerun(self) -> None:
        self.status.setText("Проверка выполняется…")
        self.b_run.setEnabled(False)
        self.rerun_requested.emit()

    def set_items(self, items: list[DiagnosticItem]) -> None:
        self._items = items
        self.b_run.setEnabled(True)
        while self.box.count():
            it = self.box.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
        ok = sum(1 for i in items if i.state.value == "available")
        self.status.setText(f"Проверок: {len(items)}, доступно полностью: {ok}")
        for it in items:
            c = Card(padding=14)
            h = QHBoxLayout()
            t = QLabel(f"<b>{it.title}</b>")
            t.setTextFormat(Qt.RichText)
            h.addWidget(t)
            h.addStretch(1)
            chip = Chip()
            chip.set_state(it.state)
            h.addWidget(chip)
            c.lay.addLayout(h)
            m = QLabel(it.message)
            m.setWordWrap(True)
            m.setTextInteractionFlags(Qt.TextSelectableByMouse)
            c.lay.addWidget(m)
            if it.explanation:
                e = QLabel(it.explanation)
                e.setObjectName("Muted")
                e.setWordWrap(True)
                e.setTextInteractionFlags(Qt.TextSelectableByMouse)
                c.lay.addWidget(e)
            self.box.addWidget(c)

    def _copy(self) -> None:
        QGuiApplication.clipboard().setText(diagnostics_report(self._items))
        self.copied.setText("Скопировано в буфер обмена")
