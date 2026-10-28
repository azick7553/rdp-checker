"""Фоновый поток мониторинга (QThread). GUI никогда не блокируется опросом Windows API."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta

from PySide6.QtCore import QObject, QThread, QTimer, Signal, Slot

from core.connection_detector import ConnectionDetector
from core.diagnostics import run_diagnostics

log = logging.getLogger(__name__)


class MonitorWorker(QObject):
    cycle_done = Signal(object)          # CycleResult
    diagnostics_done = Signal(object)    # list[DiagnosticItem]
    paused_changed = Signal(bool)
    error = Signal(str)

    def __init__(self, detector: ConnectionDetector, interval_s: int = 2, storage=None, retention_days: int = 30) -> None:
        super().__init__()
        self.detector = detector
        self.interval_ms = max(1, min(30, interval_s)) * 1000
        self.storage = storage
        self.retention_days = retention_days
        self._timer: QTimer | None = None
        self._paused = False
        self._failures = 0
        self._last_purge: datetime | None = None
        self.last_cycle: datetime | None = None
        self.notifications_available: bool | None = None

    @Slot()
    def start(self) -> None:
        self._timer = QTimer(self)
        self._timer.setSingleShot(False)
        self._timer.timeout.connect(self._tick)
        self._timer.start(self.interval_ms)
        QTimer.singleShot(0, lambda: self._tick(force=True))

    @Slot()
    def stop(self) -> None:
        if self._timer:
            self._timer.stop()

    @Slot()
    def refresh(self) -> None:
        if not self._paused:
            self._tick(force=True)

    @Slot(int)
    def set_interval(self, seconds: int) -> None:
        self.interval_ms = max(1, min(30, int(seconds))) * 1000
        if self._timer and not self._paused:
            self._timer.start(self.interval_ms)

    @Slot(int)
    def set_retention(self, days: int) -> None:
        self.retention_days = days
        self._last_purge = None

    @Slot(bool)
    def set_paused(self, paused: bool) -> None:
        self._paused = paused
        if self._timer:
            if paused:
                self._timer.stop()
            else:
                self._timer.start(self.interval_ms)
                QTimer.singleShot(0, lambda: self._tick(force=True))
        self.paused_changed.emit(paused)

    @Slot()
    def run_diagnostics(self) -> None:
        try:
            alive = self._timer is not None and (self._paused or self._timer.isActive())
            items = run_diagnostics(self.detector, self.notifications_available,
                                    worker_alive=None if self._paused else alive, last_cycle=self.last_cycle)
            self.diagnostics_done.emit(items)
        except Exception as e:  # noqa: BLE001
            log.exception("Diagnostics failed")
            self.error.emit(f"Диагностика: {e}")

    def _tick(self, force: bool = False) -> None:
        if self._paused:
            return
        try:
            result = self.detector.run_cycle(force=force)
            self.last_cycle = result.timestamp
            self._failures = 0
            if self._timer and self._timer.interval() != self.interval_ms:
                self._timer.start(self.interval_ms)
            self.cycle_done.emit(result)
        except Exception as e:  # noqa: BLE001 — восстановление после временных ошибок
            self._failures += 1
            log.exception("Monitoring cycle failed (%d)", self._failures)
            self.error.emit(str(e))
            if self._timer:
                backoff = min(30_000, self.interval_ms * (2 ** min(self._failures, 4)))
                self._timer.start(backoff)
        self._maybe_purge()

    def _maybe_purge(self) -> None:
        if self.storage is None:
            return
        now = datetime.now()
        if self._last_purge and now - self._last_purge < timedelta(hours=1):
            return
        self._last_purge = now
        try:
            n = self.storage.purge(self.retention_days)
            if n:
                log.info("Purged %d old events", n)
        except Exception as e:  # noqa: BLE001
            log.warning("Purge failed: %s", e)


class MonitorThread:
    """Владелец QThread + MonitorWorker с корректной остановкой."""

    def __init__(self, worker: MonitorWorker) -> None:
        self.worker = worker
        self.thread = QThread()
        self.thread.setObjectName("MonitorThread")
        worker.moveToThread(self.thread)
        self.thread.started.connect(worker.start)

    def start(self) -> None:
        self.thread.start()

    def is_running(self) -> bool:
        return self.thread.isRunning()

    def shutdown(self, timeout_ms: int = 5000) -> None:
        if not self.thread.isRunning():
            return
        from PySide6.QtCore import QMetaObject, Qt
        QMetaObject.invokeMethod(self.worker, "stop", Qt.BlockingQueuedConnection)
        self.thread.quit()
        if not self.thread.wait(timeout_ms):
            log.warning("Monitor thread did not stop in time")
