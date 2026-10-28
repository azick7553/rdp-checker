"""Значок в системном трее Windows: цвет состояния, меню, всплывающие уведомления."""
from __future__ import annotations

from PySide6.QtCore import QObject, QTimer, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from core.models import OverallStatus
from gui import theme
from services.notifications import SEVERITY_CRITICAL, SEVERITY_WARNING, Notification

TOOLTIPS = {
    OverallStatus.NO_CONNECTIONS: "Удалённых подключений не обнаружено",
    OverallStatus.CONNECTED: "ОБНАРУЖЕНО активное удалённое подключение",
    OverallStatus.INSUFFICIENT: "Мониторинг частично недоступен или есть неподтверждённые признаки",
    OverallStatus.STOPPED: "Мониторинг остановлен",
}


class TrayManager(QObject):
    open_requested = Signal()
    sessions_requested = Signal()
    settings_requested = Signal()
    pause_toggled = Signal(bool)   # True — поставить на паузу
    quit_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.available = QSystemTrayIcon.isSystemTrayAvailable()
        self.icons = {s: theme.status_icon(s) for s in OverallStatus}
        self.tray = QSystemTrayIcon(self.icons[OverallStatus.STOPPED], self)
        self.tray.setToolTip("RDP Connection Monitor")
        menu = QMenu()
        a_open = QAction("Открыть приложение", menu)
        a_sessions = QAction("Показать активные подключения", menu)
        self.a_pause = QAction("Приостановить мониторинг", menu)
        a_settings = QAction("Настройки", menu)
        a_quit = QAction("Выход", menu)
        a_open.triggered.connect(self.open_requested)
        a_sessions.triggered.connect(self.sessions_requested)
        self.a_pause.triggered.connect(self._toggle_pause)
        a_settings.triggered.connect(self.settings_requested)
        a_quit.triggered.connect(self.quit_requested)
        for a in (a_open, a_sessions):
            menu.addAction(a)
        menu.addSeparator()
        menu.addAction(self.a_pause)
        menu.addAction(a_settings)
        menu.addSeparator()
        menu.addAction(a_quit)
        self._menu = menu
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._on_activated)
        self.tray.messageClicked.connect(self.open_requested)
        self._paused = False
        self._status = OverallStatus.STOPPED
        # мигание индикатора при активном подключении
        self._blink = QTimer(self)
        self._blink.setInterval(800)
        self._blink.timeout.connect(self._on_blink)
        self._blink_on = True

    @property
    def supports_messages(self) -> bool:
        return self.available and QSystemTrayIcon.supportsMessages()

    def show(self) -> None:
        self.tray.show()

    def hide(self) -> None:
        self._blink.stop()
        self.tray.hide()

    def _toggle_pause(self) -> None:
        self.pause_toggled.emit(not self._paused)

    def set_paused(self, paused: bool) -> None:
        self._paused = paused
        self.a_pause.setText("Возобновить мониторинг" if paused else "Приостановить мониторинг")
        if paused:
            self.set_status(OverallStatus.STOPPED)

    def set_status(self, status: OverallStatus, detail: str = "") -> None:
        if self._paused and status != OverallStatus.STOPPED:
            return
        previous = self._status
        self._status = status
        self.tray.setIcon(self.icons[status])
        tip = f"RDP Connection Monitor\n{TOOLTIPS[status]}"
        if detail:
            tip += f"\n{detail}"
        self.tray.setToolTip(tip[:127])
        if status == OverallStatus.CONNECTED and previous != OverallStatus.CONNECTED:
            # 20 секунд мигаем, затем значок остаётся красным
            self._blink.start()
            QTimer.singleShot(20000, self._stop_blink)
        elif status != OverallStatus.CONNECTED:
            self._blink.stop()

    def _stop_blink(self) -> None:
        self._blink.stop()
        self.tray.setIcon(self.icons[self._status])

    def _on_blink(self) -> None:
        self._blink_on = not self._blink_on
        self.tray.setIcon(self.icons[OverallStatus.CONNECTED if self._blink_on else OverallStatus.STOPPED])

    def _on_activated(self, reason) -> None:
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.open_requested.emit()

    def notify(self, n: Notification) -> None:
        icon = (QSystemTrayIcon.Critical if n.severity == SEVERITY_CRITICAL
                else QSystemTrayIcon.Warning if n.severity == SEVERITY_WARNING else QSystemTrayIcon.Information)
        self.tray.showMessage(n.title, n.body, icon, 15000 if n.severity == SEVERITY_CRITICAL else 8000)
