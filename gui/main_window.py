"""Главное окно: боковая навигация, заголовок, страницы."""
from __future__ import annotations

import logging

from PySide6.QtCore import QSize, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QButtonGroup, QHBoxLayout, QLabel, QMainWindow, QPushButton, QStackedWidget, QVBoxLayout, QWidget,
)

from app.config import APP_NAME, APP_VERSION, Settings
from core import winapi
from core.models import CycleResult, OverallStatus
from gui import theme
from gui.dashboard import DashboardView
from gui.diagnostics_view import DiagnosticsView
from gui.history_view import HistoryView
from gui.remote_tools_view import RemoteToolsView
from gui.sessions_view import SessionsView
from gui.settings_view import SettingsView

log = logging.getLogger(__name__)

WM_WTSSESSION_CHANGE = 0x02B1
PAGES = [
    ("dashboard", "Обзор"),
    ("sessions", "Сеансы"),
    ("history", "История подключений"),
    ("tools", "Другие средства"),
    ("diagnostics", "Диагностика"),
    ("settings", "Настройки"),
]


class MainWindow(QMainWindow):
    refresh_requested = Signal()
    pause_toggled = Signal(bool)
    session_change = Signal(int)        # WM_WTSSESSION_CHANGE (код события)
    hidden_to_tray = Signal()
    quit_requested = Signal()

    def __init__(self, settings: Settings, storage, data_dir: str, log_path: str, tray_available: bool = True) -> None:
        super().__init__()
        self.settings = settings
        self.storage = storage
        self.tray_available = tray_available
        self._really_quit = False
        self._wts_registered = False
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(theme.status_icon(OverallStatus.NO_CONNECTIONS))
        self.resize(1180, 780)
        self.setMinimumSize(QSize(900, 600))

        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)

        # --- боковая панель
        side = QWidget()
        side.setObjectName("Sidebar")
        side.setFixedWidth(232)
        sv = QVBoxLayout(side)
        sv.setContentsMargins(10, 18, 10, 14)
        sv.setSpacing(3)
        brand = QHBoxLayout()
        self.brand_icon = QLabel()
        self.brand_icon.setStyleSheet("background: transparent;")
        self.brand_icon.setPixmap(theme.status_icon(OverallStatus.STOPPED).pixmap(28, 28))
        t = QLabel("RDP Monitor")
        t.setObjectName("AppTitle")
        brand.addWidget(self.brand_icon)
        brand.addWidget(t, 1)
        sv.addLayout(brand)
        sv.addSpacing(18)
        self.nav = QButtonGroup(self)
        self.nav.setExclusive(True)
        self.nav_buttons: dict[str, QPushButton] = {}
        for i, (key, title) in enumerate(PAGES):
            b = QPushButton(f"  {title}")
            b.setIcon(theme.nav_icon(key))
            b.setIconSize(QSize(18, 18))
            b.setCheckable(True)
            b.setCursor(Qt.PointingHandCursor)
            self.nav.addButton(b, i)
            self.nav_buttons[key] = b
            sv.addWidget(b)
        sv.addStretch(1)
        info = winapi.system_info()
        self.sysinfo = QLabel(f"{info['computer']}\n{info['user']}\n{info['os']}\nверсия {APP_VERSION}")
        self.sysinfo.setObjectName("SysInfo")
        self.sysinfo.setToolTip(f"{info['os']} — {info['os_version']}")
        sv.addWidget(self.sysinfo)
        h.addWidget(side)

        # --- правая часть
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.setSpacing(0)
        top = QWidget()
        top.setStyleSheet(f"background: {theme.BG};")
        tl = QHBoxLayout(top)
        tl.setContentsMargins(28, 16, 28, 0)
        title_box = QVBoxLayout()
        title = QLabel("RDP Connection Monitor")
        title.setObjectName("PageTitle")
        subtitle = QLabel("Мониторинг удалённых подключений")
        subtitle.setObjectName("PageSubtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        tl.addLayout(title_box, 1)
        self.last_check = QLabel("")
        self.last_check.setObjectName("Muted")
        tl.addWidget(self.last_check)
        self.b_refresh = QPushButton("Обновить")
        self.b_refresh.setToolTip("Проверить состояние сейчас")
        self.b_pause = QPushButton("Пауза")
        self.b_pause.setCheckable(True)
        self.b_pause.setToolTip("Приостановить / возобновить мониторинг")
        tl.addWidget(self.b_refresh)
        tl.addWidget(self.b_pause)
        rv.addWidget(top)

        self.stack = QStackedWidget()
        self.dashboard = DashboardView(storage)
        self.sessions = SessionsView()
        self.history = HistoryView(storage)
        self.tools = RemoteToolsView()
        self.diagnostics = DiagnosticsView(data_dir, log_path)
        self.settings_view = SettingsView(settings)
        for w in (self.dashboard, self.sessions, self.history, self.tools, self.diagnostics, self.settings_view):
            self.stack.addWidget(w)
        rv.addWidget(self.stack, 1)
        h.addWidget(right, 1)

        self.nav.idClicked.connect(self.stack.setCurrentIndex)
        self.nav_buttons["dashboard"].setChecked(True)
        self.dashboard.open_sessions.connect(lambda: self.show_page("sessions"))
        self.dashboard.open_history.connect(lambda: self.show_page("history"))
        self.b_refresh.clicked.connect(self._on_refresh)
        self.b_pause.toggled.connect(self.pause_toggled)

    # ------------------------------------------------------------------ pages
    def show_page(self, key: str) -> None:
        idx = [k for k, _ in PAGES].index(key)
        self.nav_buttons[key].setChecked(True)
        self.stack.setCurrentIndex(idx)

    def bring_to_front(self, page: str | None = None) -> None:
        if page:
            self.show_page(page)
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _on_refresh(self) -> None:
        self.last_check.setText("Проверка…")
        self.refresh_requested.emit()

    def set_paused(self, paused: bool) -> None:
        self.b_pause.blockSignals(True)
        self.b_pause.setChecked(paused)
        self.b_pause.blockSignals(False)
        self.b_pause.setText("Продолжить" if paused else "Пауза")
        self.dashboard.set_paused(paused)
        if paused:
            self.last_check.setText("Мониторинг приостановлен")

    # ------------------------------------------------------------------ data
    def update_cycle(self, r: CycleResult) -> None:
        self.last_check.setText(f"Последняя проверка: {r.timestamp:%H:%M:%S}")
        self.dashboard.update_cycle(r)
        self.sessions.update_cycle(r)
        if self.settings.remote_tools_enabled:
            self.tools.update_tools(r.remote_tools)
        if r.new_events:
            self.history.mark_dirty()
        icon = theme.status_icon(r.overall)
        self.setWindowIcon(icon)
        self.brand_icon.setPixmap(icon.pixmap(28, 28))

    # ------------------------------------------------------------------ WTS notifications
    def register_wts_notifications(self) -> None:
        if not winapi.IS_WINDOWS:
            return
        try:
            self._wts_registered = winapi.register_session_notification(int(self.winId()), all_sessions=True)
        except Exception as e:  # noqa: BLE001
            log.info("WTSRegisterSessionNotification failed: %s", e)

    def unregister_wts_notifications(self) -> None:
        if self._wts_registered:
            try:
                winapi.unregister_session_notification(int(self.winId()))
            except Exception:  # noqa: BLE001
                pass
            self._wts_registered = False

    def nativeEvent(self, event_type, message):  # noqa: N802
        if winapi.IS_WINDOWS and self._wts_registered:
            try:
                if bytes(event_type) == b"windows_generic_MSG":
                    from ctypes import wintypes
                    msg = wintypes.MSG.from_address(int(message))
                    if msg.message == WM_WTSSESSION_CHANGE:
                        code = int(msg.wParam)
                        QTimer.singleShot(400, lambda c=code: self.session_change.emit(c))
            except Exception:  # noqa: BLE001
                pass
        return super().nativeEvent(event_type, message)

    # ------------------------------------------------------------------ close
    def allow_quit(self) -> None:
        self._really_quit = True

    def closeEvent(self, event):  # noqa: N802
        if not self._really_quit and self.settings.minimize_to_tray and self.tray_available:
            event.ignore()
            self.hide()
            self.hidden_to_tray.emit()
            return
        if not self._really_quit:
            event.ignore()
            self.quit_requested.emit()
            return
        self.unregister_wts_notifications()
        event.accept()
