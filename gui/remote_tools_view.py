"""Вкладка «Другие средства удалённого доступа»."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QCheckBox, QHBoxLayout, QLabel, QScrollArea, QVBoxLayout, QWidget

from core.models import TOOL_CONNECTION_RU, RemoteToolStatus, ToolConnectionStatus
from gui import theme
from gui.widgets import Card, Chip, page_header


def _row(label: str, chip: Chip) -> QHBoxLayout:
    h = QHBoxLayout()
    lbl = QLabel(label)
    lbl.setObjectName("Muted")
    lbl.setMinimumWidth(150)
    h.addWidget(lbl)
    h.addWidget(chip)
    h.addStretch(1)
    return h


class ToolCard(Card):
    def __init__(self, t: RemoteToolStatus) -> None:
        super().__init__(padding=14)
        if t.suspicious and t.running:
            self.setStyleSheet(f"#Card {{ background: {theme.YELLOW_BG}; border: 1px solid {theme.rgba(theme.YELLOW, 0.5)};"
                               f" border-radius: 10px; }}")
        head = QHBoxLayout()
        name = QLabel(f"<b>{t.name}</b>")
        name.setTextFormat(Qt.RichText)
        cat = QLabel(t.category)
        cat.setObjectName("Muted")
        head.addWidget(name)
        head.addStretch(1)
        head.addWidget(cat)
        self.lay.addLayout(head)

        found = Chip("Программа обнаружена" if t.installed else "Не обнаружена",
                     theme.TEXT if t.installed else theme.MUTED, theme.SURFACE_HOVER if t.installed else theme.SURFACE_2)
        run = Chip("Процесс запущен" if t.running else "Не запущена",
                   theme.YELLOW if t.running else theme.MUTED, theme.YELLOW_BG if t.running else theme.SURFACE_2)
        if t.connection == ToolConnectionStatus.CONFIRMED:
            conn = Chip(TOOL_CONNECTION_RU[t.connection], theme.RED, theme.RED_BG)
        elif t.connection == ToolConnectionStatus.EVIDENCE:
            text = TOOL_CONNECTION_RU[t.connection]
            if t.last_incoming:
                text += f" (последнее: {t.last_incoming:%d.%m.%Y %H:%M})"
            conn = Chip(text, theme.YELLOW, theme.YELLOW_BG)
        elif t.connection == ToolConnectionStatus.UNKNOWN:
            conn = Chip(TOOL_CONNECTION_RU[t.connection], theme.TEXT_2, theme.SURFACE_2)
        else:
            conn = Chip("Нет признаков", theme.MUTED, theme.SURFACE_2)
        self.lay.addLayout(_row("Наличие", found))
        self.lay.addLayout(_row("Процесс", run))
        self.lay.addLayout(_row("Подключение", conn))
        details = []
        if t.install_path:
            details.append(f"Путь: {t.install_path}")
        if t.processes:
            details.append("Процессы: " + "; ".join(t.processes))
        if t.note:
            details.append(t.note)
        if details:
            d = QLabel("\n".join(details))
            d.setObjectName("Muted")
            d.setWordWrap(True)
            d.setTextInteractionFlags(Qt.TextSelectableByMouse)
            self.lay.addWidget(d)


class RemoteToolsView(QScrollArea):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        body = QWidget()
        self.setWidget(body)
        lay = QVBoxLayout(body)
        lay.setContentsMargins(28, 22, 28, 22)
        lay.setSpacing(12)
        lay.addWidget(page_header(
            "Другие средства удалённого доступа",
            "Наличие запущенного процесса не означает, что к компьютеру кто-то подключён. "
            "Монитор не читает память других программ; подключение считается подтверждённым только "
            "при наличии прямых доказательств. Записи о входящих подключениях берутся из журналов, "
            "которые AnyDesk и TeamViewer ведут сами, если они доступны для чтения."))
        self.show_all = QCheckBox("Показать все проверяемые программы")
        lay.addWidget(self.show_all)
        self.summary = QLabel("Проверка…")
        self.summary.setObjectName("Muted")
        self.summary.setWordWrap(True)
        lay.addWidget(self.summary)
        self.box = QVBoxLayout()
        self.box.setSpacing(10)
        lay.addLayout(self.box)
        note = QLabel("Не обнаруживаются: демонстрация экрана в Teams/Zoom/Telegram, корпоративные агенты, "
                      "работающие как системные службы без видимых процессов в этом списке, а также "
                      "аппаратные средства (Intel AMT/KVM). Для них нужны средства с правами администратора.")
        note.setObjectName("Footnote")
        note.setWordWrap(True)
        lay.addWidget(note)
        lay.addStretch(1)
        self._last: list[RemoteToolStatus] = []
        self.show_all.toggled.connect(lambda _: self.update_tools(self._last))

    def update_tools(self, tools: list[RemoteToolStatus]) -> None:
        sig = (self.show_all.isChecked(), tuple(
            (t.key, t.installed, t.running, tuple(t.processes), t.connection, t.last_incoming) for t in tools))
        if sig == getattr(self, "_sig", None):
            return
        self._sig = sig
        self._last = tools
        while self.box.count():
            it = self.box.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
        shown = [t for t in tools if self.show_all.isChecked() or t.installed or t.running
                 or t.connection != ToolConnectionStatus.NOT_RUNNING]
        running = [t for t in tools if t.running]
        self.summary.setText(
            f"Проверено программ: {len(tools)}. Обнаружено: {len([t for t in tools if t.installed])}. "
            f"Запущено: {len(running)}." + ("" if shown else " Известные средства удалённого доступа не найдены."))
        for t in shown:
            self.box.addWidget(ToolCard(t))
