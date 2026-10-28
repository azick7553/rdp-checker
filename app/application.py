"""Сборка приложения: настройки, хранилище, детектор, фоновый поток, окно, трей, уведомления."""
from __future__ import annotations

import logging
import sys
from typing import Optional

from PySide6.QtCore import QObject, Qt, QTimer, Signal, Slot
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication, QMessageBox

from app.config import APP_ID, APP_NAME, APP_VERSION, Settings, data_dir
from app.monitor_worker import MonitorThread, MonitorWorker
from app.single_instance import SingleInstance
from core.connection_detector import ConnectionDetector
from core.eventlog_monitor import EventLogMonitor
from core.models import Confidence, ConnectionEvent, CycleResult, EventType, OverallStatus
from core.remote_tools_detector import RemoteToolsDetector
from gui import theme
from gui.main_window import MainWindow
from gui.tray_manager import TrayManager
from services.logger import setup_logging
from services.notifications import NotificationService, format_notification, play_sound
from services.storage import Storage

log = logging.getLogger(__name__)


class _Bridge(QObject):
    """Сигналы GUI → фоновый поток (вызовы слотов выполняются в потоке мониторинга)."""
    refresh = Signal()
    set_interval = Signal(int)
    set_retention = Signal(int)
    set_paused = Signal(bool)
    diagnostics = Signal()


def build_detector(settings: Settings, storage: Optional[Storage]) -> ConnectionDetector:
    tools = RemoteToolsDetector() if settings.remote_tools_enabled else RemoteToolsDetector(tools=())
    return ConnectionDetector(
        eventlog=EventLogMonitor(lookback_days=settings.eventlog_lookback_days,
                                 include_security=settings.read_security_log),
        tools=tools, storage=storage,
    )


class Application(QObject):
    """QObject в главном потоке: сигналы из потока мониторинга доставляются сюда через очередь событий Qt."""

    def __init__(self, argv: list[str]) -> None:
        self.log_path = setup_logging()
        log.info("Starting %s %s", APP_NAME, APP_VERSION)
        QGuiApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
        self.app = QApplication.instance() or QApplication(argv)
        self.app.setApplicationName(APP_NAME)
        self.app.setOrganizationName(APP_ID)
        self.app.setApplicationVersion(APP_VERSION)
        super().__init__()
        self.app.setQuitOnLastWindowClosed(False)
        self.app.setStyle("Fusion")
        self.app.setFont(theme.app_font())
        self.app.setStyleSheet(theme.QSS)
        self.start_minimized_flag = "--minimized" in argv
        self.instance = SingleInstance()
        self.ok = True

    # ------------------------------------------------------------------
    def setup(self) -> bool:
        first = self.instance.acquire_mutex()
        if not first:
            log.info("Another instance is running — activating it and exiting")
            self.instance.notify_existing("show")
            return False
        if self.instance.notify_existing("show"):
            log.info("Another instance answered — exiting")
            return False
        if not self.instance.listen():
            log.warning("Single-instance server could not listen")
        self.instance.activated.connect(self._on_activated)

        self.settings = Settings.load()
        self.data_dir = data_dir()
        try:
            self.storage = Storage(self.data_dir / "history.db")
            self.storage.purge(self.settings.retention_days)
        except Exception as e:  # noqa: BLE001
            log.exception("Cannot open database")
            QMessageBox.critical(None, APP_NAME, f"Не удалось открыть базу истории:\n{e}")
            return False

        self.tray = TrayManager()
        self.window = MainWindow(self.settings, self.storage, str(self.data_dir), str(self.log_path),
                                 tray_available=self.tray.available)
        self.notifier = NotificationService(self.settings, self._show_notification, self._play_sound)

        self.detector = build_detector(self.settings, self.storage)
        self.worker = MonitorWorker(self.detector, self.settings.poll_interval, self.storage, self.settings.retention_days)
        self.worker.notifications_available = self.tray.supports_messages
        self.thread = MonitorThread(self.worker)
        self.bridge = _Bridge()
        self.bridge.refresh.connect(self.worker.refresh)
        self.bridge.set_interval.connect(self.worker.set_interval)
        self.bridge.set_retention.connect(self.worker.set_retention)
        self.bridge.set_paused.connect(self.worker.set_paused)
        self.bridge.diagnostics.connect(self.worker.run_diagnostics)

        self.worker.cycle_done.connect(self._on_cycle)
        self.worker.diagnostics_done.connect(self.window.diagnostics.set_items)
        self.worker.paused_changed.connect(self._on_paused)
        self.worker.error.connect(self._on_worker_error)

        w = self.window
        w.refresh_requested.connect(self.bridge.refresh)
        w.pause_toggled.connect(self.bridge.set_paused)
        w.session_change.connect(lambda _code: self.bridge.refresh.emit())
        w.quit_requested.connect(self.quit)
        w.hidden_to_tray.connect(self._on_hidden)
        w.diagnostics.rerun_requested.connect(self.bridge.diagnostics)
        w.settings_view.settings_changed.connect(self._on_settings)
        w.settings_view.test_notification.connect(self._test_notification)
        w.settings_view.test_sound.connect(lambda: self._play_sound(None))
        w.settings_view.clear_history.connect(self._clear_history)

        t = self.tray
        t.open_requested.connect(lambda: w.bring_to_front())
        t.sessions_requested.connect(self._show_active)
        t.settings_requested.connect(lambda: w.bring_to_front("settings"))
        t.pause_toggled.connect(self.bridge.set_paused)
        t.quit_requested.connect(self.quit)
        if t.available:
            t.show()

        self.app.aboutToQuit.connect(self._shutdown)
        self.thread.start()
        QTimer.singleShot(1500, self.bridge.diagnostics.emit)

        minimized = (self.settings.start_minimized or self.start_minimized_flag) and t.available
        if not minimized:
            w.show()
        w.register_wts_notifications()
        self._hidden_hint_shown = False
        return True

    def run(self) -> int:
        if not self.setup():
            return 0
        return self.app.exec()

    # ------------------------------------------------------------------ slots
    @Slot(object)
    def _on_cycle(self, r: CycleResult) -> None:
        self.window.update_cycle(r)
        detail = ""
        if r.overall == OverallStatus.CONNECTED and r.remote_sessions:
            s = r.remote_sessions[0]
            detail = f"{s.full_user or '?'} · {s.client_ip or 'IP недоступен'}"
        self.tray.set_status(r.overall, detail)
        if r.notify_events:
            self.notifier.handle(r.notify_events)

    @Slot(str)
    def _on_worker_error(self, message: str) -> None:
        log.warning("Worker error: %s", message)

    def _show_notification(self, n) -> None:
        if self.tray.available:
            self.tray.notify(n)

    def _play_sound(self, n) -> None:
        sev = n.severity if n else "warning"
        play_sound(self.settings.sound, self.settings.custom_sound_path, sev, fallback=QApplication.beep)

    @Slot(bool)
    def _on_paused(self, paused: bool) -> None:
        self.window.set_paused(paused)
        self.tray.set_paused(paused)
        if not paused:
            self.bridge.refresh.emit()

    def _on_settings(self, s: Settings) -> None:
        self.bridge.set_interval.emit(s.poll_interval)
        self.bridge.set_retention.emit(s.retention_days)
        self.notifier.settings = s
        log.info("Settings updated: interval=%s", s.poll_interval)

    def _on_hidden(self) -> None:
        if not self._hidden_hint_shown and self.tray.supports_messages:
            self._hidden_hint_shown = True
            self.tray.tray.showMessage(APP_NAME, "Приложение свёрнуто в трей. Мониторинг продолжается.",
                                       self.tray.tray.icon(), 4000)

    def _show_active(self) -> None:
        self.window.sessions.show_remote_only()
        self.window.bring_to_front("sessions")

    def _on_activated(self, msg: str) -> None:
        self.window.bring_to_front()

    def _test_notification(self) -> None:
        from datetime import datetime
        ev = ConnectionEvent(datetime.now().astimezone(), EventType.RDP_CONNECT, "Тест", Confidence.INFO,
                             user="ТЕСТ\\пример", ip="", session_id=None, details="Тестовое уведомление")
        n = format_notification(ev)
        n.title = "Тестовое уведомление"
        if self.tray.supports_messages:
            self.tray.notify(n)
        else:
            QMessageBox.information(self.window, APP_NAME, "Системные уведомления недоступны в этой системе.")
        self._play_sound(n)

    def _clear_history(self) -> None:
        self.storage.clear()
        self.window.history.reload()
        self.window.dashboard.refresh_stats()

    def quit(self) -> None:
        self.window.allow_quit()
        self.window.close()
        self.app.quit()

    def _shutdown(self) -> None:
        log.info("Shutting down")
        try:
            self.thread.shutdown()
        except Exception:  # noqa: BLE001
            log.exception("Thread shutdown failed")
        self.window.unregister_wts_notifications()
        self.tray.hide()
        self.instance.close()
        try:
            self.storage.close()
        except Exception:  # noqa: BLE001
            pass


def main(argv: Optional[list[str]] = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    return Application(argv).run()
