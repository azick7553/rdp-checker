"""Главная страница: основной статус, статистика, активные удалённые сеансы, последние события."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget

from core.connection_detector import today_start
from core.models import Confidence, CycleResult, OverallStatus
from gui import theme
from gui.widgets import Card, SectionTitle, StatCard, StatusCard, fmt_dt


class DashboardView(QScrollArea):
    open_sessions = Signal()
    open_history = Signal()

    def __init__(self, storage, parent=None) -> None:
        super().__init__(parent)
        self.storage = storage
        self.setWidgetResizable(True)
        body = QWidget()
        self.setWidget(body)
        lay = QVBoxLayout(body)
        lay.setContentsMargins(28, 22, 28, 22)
        lay.setSpacing(16)

        self.status = StatusCard()
        lay.addWidget(self.status)

        grid = QGridLayout()
        grid.setSpacing(12)
        self.c_active = StatCard("Активные RDP-сеансы", "—")
        self.c_today = StatCard("Подключения за сегодня", "—")
        self.c_last = StatCard("Последнее подключение", "—")
        self.c_check = StatCard("Последняя проверка", "—")
        for i, c in enumerate((self.c_active, self.c_today, self.c_last, self.c_check)):
            grid.addWidget(c, 0, i)
        lay.addLayout(grid)

        head = QHBoxLayout()
        head.addWidget(SectionTitle("Удалённые сеансы сейчас"))
        head.addStretch(1)
        b = QPushButton("Все сеансы")
        b.clicked.connect(self.open_sessions)
        head.addWidget(b)
        lay.addLayout(head)
        self.sessions_box = QVBoxLayout()
        self.sessions_box.setSpacing(8)
        lay.addLayout(self.sessions_box)

        head = QHBoxLayout()
        head.addWidget(SectionTitle("Последние события"))
        head.addStretch(1)
        b = QPushButton("История")
        b.clicked.connect(self.open_history)
        head.addWidget(b)
        lay.addLayout(head)
        self.events_card = Card()
        self.events_label = QLabel("Событий пока нет")
        self.events_label.setTextFormat(Qt.RichText)
        self.events_label.setWordWrap(True)
        self.events_label.setObjectName("Muted")
        self.events_card.lay.addWidget(self.events_label)
        lay.addWidget(self.events_card)

        note = QLabel(
            "Важно: монитор показывает то, что Windows разрешает видеть обычному пользователю. "
            "Отсутствие обнаруженного RDP-сеанса не гарантирует, что за экраном никто не наблюдает "
            "через другое средство (корпоративное ПО удалённого управления, демонстрацию экрана в мессенджере и т.п.). "
            "Подробности — на вкладке «Диагностика».")
        note.setObjectName("Footnote")
        note.setWordWrap(True)
        lay.addWidget(note)
        lay.addStretch(1)
        self._paused = False

    # ------------------------------------------------------------------
    def set_paused(self, paused: bool) -> None:
        self._paused = paused
        if paused:
            self.status.set_status(OverallStatus.STOPPED, "Мониторинг приостановлен",
                                   ["Новые подключения не отслеживаются, пока мониторинг на паузе."], "")

    def update_cycle(self, r: CycleResult) -> None:
        if self._paused:
            return
        meta = f"Проверено в {r.timestamp:%H:%M:%S} · цикл {r.cycle_ms:.0f} мс"
        if r.errors:
            meta += f" · предупреждений: {len(r.errors)}"
        self.status.set_status(r.overall, r.overall_title, r.overall_reasons, meta)

        remote = r.remote_sessions
        color = theme.RED if remote else theme.GREEN if r.overall != OverallStatus.INSUFFICIENT else None
        self.c_active.set(str(len(remote)) if r.sources.get("wts") and r.sources["wts"].usable else "?",
                          "сеансов по RDP" if r.sources.get("wts") and r.sources["wts"].usable else "нет данных WTS",
                          color)
        self.c_check.set(f"{r.timestamp:%H:%M:%S}", "мониторинг активен")
        self.refresh_stats()
        self._fill_sessions(r)

    def refresh_stats(self) -> None:
        try:
            n = self.storage.count_connections_since(today_start())
            self.c_today.set(str(n), "по WTS API и журналу LSM")
            last = self.storage.last_connection()
            if last:
                self.c_last.set(fmt_dt(last.timestamp, with_date=False) if last.timestamp.date() == datetime.now().date()
                                else last.timestamp.strftime("%d.%m %H:%M"),
                                f"{last.user or '—'} · {last.ip or 'IP недоступен'}")
            else:
                self.c_last.set("—", "подключений не зарегистрировано")
            rows = self.storage.query(limit=6, min_confidence=1)
        except Exception as e:  # noqa: BLE001
            self.events_label.setText(f"Не удалось прочитать историю: {e}")
            return
        if not rows:
            self.events_label.setText("Событий пока нет")
            return
        lines = []
        for row in rows:
            color = theme.RED if row.confidence >= 3 and row.event_type in (
                "rdp_connect", "rdp_reconnect", "rdp_active_at_start", "shadow_start") else theme.TEXT_2
            lines.append(
                f"<div style='margin:3px 0'><span style='color:{theme.MUTED}'>{row.timestamp:%d.%m %H:%M:%S}</span>"
                f"&nbsp;&nbsp;<b style='color:{color}'>{row.type_label}</b>"
                f"&nbsp;&nbsp;{row.user or ''} {('· ' + row.ip) if row.ip else ''}"
                f"&nbsp;&nbsp;<span style='color:{theme.MUTED}'>[{row.confidence_label}]</span></div>")
        self.events_label.setText("".join(lines))

    def _fill_sessions(self, r: CycleResult) -> None:
        wts_ok = bool(r.sources.get("wts") and r.sources["wts"].usable)
        sig = (wts_ok, tuple((s.session_id, s.full_user, s.state, s.client_ip, s.client_name) for s in r.remote_sessions))
        if sig == getattr(self, "_sessions_sig", None):
            return
        self._sessions_sig = sig
        while self.sessions_box.count():
            item = self.sessions_box.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        remote = r.remote_sessions
        if not remote:
            c = Card(padding=14)
            text = ("Активных RDP-сеансов не обнаружено." if r.sources.get("wts") and r.sources["wts"].usable
                    else "Список сеансов недоступен — см. «Диагностика».")
            lbl = QLabel(text)
            lbl.setObjectName("Muted")
            c.lay.addWidget(lbl)
            self.sessions_box.addWidget(c)
            return
        for s in remote:
            c = Card(padding=14)
            c.setStyleSheet(f"#Card {{ background: {theme.RED_BG}; border: 1px solid {theme.rgba(theme.RED, 0.4)}; border-radius: 10px; }}")
            t = QLabel(f"<b>{s.full_user or 'Вход не выполнен (экран входа)'}</b> &nbsp;·&nbsp; сеанс {s.session_id}"
                       f" &nbsp;·&nbsp; {s.state.value}")
            t.setTextFormat(Qt.RichText)
            d = QLabel(f"IP: {s.client_ip or 'Недоступен'} &nbsp;·&nbsp; Компьютер клиента: {s.client_name or 'Недоступен'}"
                       f" &nbsp;·&nbsp; Подключён: {fmt_dt(s.display_time)}"
                       f" &nbsp;·&nbsp; Достоверность: {Confidence.CONFIRMED.label}")
            d.setTextFormat(Qt.RichText)
            d.setObjectName("Muted")
            d.setWordWrap(True)
            c.lay.addWidget(t)
            c.lay.addWidget(d)
            self.sessions_box.addWidget(c)
