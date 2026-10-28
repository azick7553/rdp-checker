"""Общие виджеты интерфейса."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt
from PySide6.QtWidgets import (
    QFrame, QGraphicsOpacityEffect, QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget,
)

from core.models import SOURCE_STATE_RU, OverallStatus, SourceState
from gui import theme


def fmt_dt(dt: Optional[datetime], with_date: bool = True) -> str:
    if not dt:
        return "—"
    today = datetime.now().astimezone().date()
    if not with_date or dt.date() == today:
        return dt.strftime("%H:%M:%S")
    return dt.strftime("%d.%m.%Y %H:%M:%S")


class Card(QFrame):
    def __init__(self, parent: Optional[QWidget] = None, padding: int = 16) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(padding, padding, padding, padding)
        self.lay.setSpacing(6)


class SectionTitle(QLabel):
    def __init__(self, text: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(text, parent)
        self.setObjectName("SectionTitle")


class StatCard(Card):
    def __init__(self, title: str, value: str = "—", hint: str = "", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.title = QLabel(title)
        self.title.setObjectName("CardTitle")
        self.value = QLabel(value)
        self.value.setObjectName("CardValue")
        self.hint = QLabel(hint)
        self.hint.setObjectName("CardHint")
        self.hint.setWordWrap(True)
        for w in (self.title, self.value, self.hint):
            self.lay.addWidget(w)
        self.lay.addStretch(1)
        self.setMinimumWidth(170)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

    def set(self, value: str, hint: str = "", color: Optional[str] = None) -> None:
        self.value.setText(value)
        self.hint.setText(hint)
        self.value.setStyleSheet(f"color: {color};" if color else "")


class Chip(QLabel):
    """Метка-«таблетка» со статусом."""

    COLORS = {
        SourceState.AVAILABLE: (theme.GREEN, theme.GREEN_BG),
        SourceState.PARTIAL: (theme.YELLOW, theme.YELLOW_BG),
        SourceState.DENIED: (theme.RED, theme.RED_BG),
        SourceState.ERROR: (theme.RED, theme.RED_BG),
    }

    def __init__(self, text: str = "", fg: str = theme.TEXT_2, bg: str = theme.SURFACE_2, parent=None) -> None:
        super().__init__(text, parent)
        self.set_colors(fg, bg)
        self.setAlignment(Qt.AlignCenter)

    def set_colors(self, fg: str, bg: str) -> None:
        self.setStyleSheet(f"background: {bg}; color: {fg}; border-radius: 10px; padding: 3px 10px; font-size: 9pt;"
                           f" font-weight: 600;")

    def set_state(self, state: SourceState) -> None:
        fg, bg = self.COLORS.get(state, (theme.TEXT_2, theme.SURFACE_2))
        self.setText(SOURCE_STATE_RU.get(state, str(state)))
        self.set_colors(fg, bg)


class StatusDot(QLabel):
    def __init__(self, size: int = 18, parent=None) -> None:
        super().__init__(parent)
        self._size = size
        self.setFixedSize(size, size)
        self.setStyleSheet("background: transparent;")

    def set_color(self, color: str) -> None:
        self.setPixmap(theme.dot_pixmap(color, self._size))


class StatusCard(QFrame):
    """Большая карточка основного статуса с плавной сменой состояния."""

    ICONS = {
        OverallStatus.NO_CONNECTIONS: "🟢",
        OverallStatus.CONNECTED: "🔴",
        OverallStatus.INSUFFICIENT: "🟡",
        OverallStatus.STOPPED: "⚪",
    }

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setObjectName("StatusCard")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(22, 20, 22, 20)
        lay.setSpacing(18)
        self.dot = StatusDot(30)
        lay.addWidget(self.dot, 0, Qt.AlignTop)
        col = QVBoxLayout()
        col.setSpacing(6)
        self.title = QLabel("Проверка…")
        self.title.setStyleSheet("font-size: 17pt; font-weight: 600; background: transparent;")
        self.title.setWordWrap(True)
        self.reasons = QLabel("")
        self.reasons.setWordWrap(True)
        self.reasons.setTextFormat(Qt.RichText)
        self.reasons.setStyleSheet(f"color: {theme.TEXT_2}; background: transparent;")
        self.meta = QLabel("")
        self.meta.setStyleSheet(f"color: {theme.MUTED}; font-size: 9pt; background: transparent;")
        col.addWidget(self.title)
        col.addWidget(self.reasons)
        col.addWidget(self.meta)
        lay.addLayout(col, 1)
        self._status: Optional[OverallStatus] = None
        self._effect = QGraphicsOpacityEffect(self)
        self._effect.setOpacity(1.0)
        self.setGraphicsEffect(self._effect)
        self._anim = QPropertyAnimation(self._effect, b"opacity", self)
        self._anim.setDuration(350)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)
        # эффект прозрачности включаем только на время анимации (иначе Windows теряет ClearType-сглаживание)
        self._effect.setEnabled(False)
        self._anim.finished.connect(lambda: self._effect.setEnabled(False))
        self.set_status(OverallStatus.INSUFFICIENT, "Первичная проверка…", [], "")

    def set_status(self, status: OverallStatus, title: str, reasons: list[str], meta: str) -> None:
        fg, bg = theme.STATUS_COLORS[status]
        changed = status != self._status
        self._status = status
        self.setStyleSheet(f"#StatusCard {{ background: {bg}; border: 1px solid {theme.rgba(fg, 0.35)}; border-left: 4px solid {fg};"
                           f" border-radius: 12px; }}")
        self.dot.set_color(fg)
        self.title.setText(title)
        if reasons:
            items = "".join(f"<li style='margin-bottom:2px'>{_esc(r)}</li>" for r in reasons[:6])
            self.reasons.setText(f"<ul style='margin:0 0 0 -24px'>{items}</ul>")
        else:
            self.reasons.setText("")
        self.meta.setText(meta)
        if changed:
            self._anim.stop()
            self._effect.setEnabled(True)
            self._anim.setStartValue(0.35)
            self._anim.setEndValue(1.0)
            self._anim.start()


def _esc(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def page_header(title: str, subtitle: str = "") -> QWidget:
    w = QWidget()
    w.setStyleSheet("background: transparent;")
    lay = QVBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 6)
    lay.setSpacing(2)
    t = QLabel(title)
    t.setObjectName("PageTitle")
    lay.addWidget(t)
    if subtitle:
        s = QLabel(subtitle)
        s.setObjectName("PageSubtitle")
        s.setWordWrap(True)
        lay.addWidget(s)
    return w
