"""Сценарии 1, 6, 7: запуск без повышения прав, работа в трее, единственный экземпляр."""
import re
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

pytest.importorskip("PySide6")
from PySide6.QtCore import QCoreApplication  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication([])
    yield app


def _wait(cond, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        QCoreApplication.processEvents()
        if cond():
            return True
        time.sleep(0.02)
    return False


# ---------------------------------------------------------------- Scenario 1
def test_manifest_requests_as_invoker_only():
    manifest = (ROOT / "rdp_monitor.manifest").read_text(encoding="utf-8")
    assert 'level="asInvoker"' in manifest
    assert "requireAdministrator" not in manifest and "highestAvailable" not in manifest
    spec = (ROOT / "rdp_monitor.spec").read_text(encoding="utf-8")
    assert "uac_admin=False" in spec


def test_no_elevation_or_system_changes_in_code():
    forbidden = [r"runas", r"ShellExecute", r"AdjustTokenPrivileges", r"SeDebugPrivilege", r"CreateService",
                 r"OpenSCManager", r"RegSetValue", r"SetValueEx", r"netsh", r"WriteProcessMemory",
                 r"ReadProcessMemory", r"CreateRemoteThread", r"reg add", r"sc create"]
    for folder in ("app", "core", "gui", "services"):
        for py in (ROOT / folder).glob("*.py"):
            text = py.read_text(encoding="utf-8")
            for pat in forbidden:
                assert not re.search(pat, text, re.IGNORECASE), f"{pat} found in {py}"


def test_registry_opened_read_only():
    text = (ROOT / "core" / "network_monitor.py").read_text(encoding="utf-8")
    assert "KEY_READ" in text and "KEY_WRITE" not in text and "KEY_ALL_ACCESS" not in text


# ---------------------------------------------------------------- Scenario 6
def test_close_hides_to_tray_and_monitoring_continues(qapp, tmp_path):
    from app.config import Settings
    from app.monitor_worker import MonitorThread, MonitorWorker
    from gui.main_window import MainWindow
    from services.storage import Storage
    from tests.fakes import FakeWts, console, make_detector

    st = Storage(tmp_path / "h.db")
    s = Settings().validate()
    w = MainWindow(s, st, str(tmp_path), "app.log", tray_available=True)
    det = make_detector(wts=FakeWts([console()]), storage=st)
    worker = MonitorWorker(det, interval_s=1)
    results = []
    worker.cycle_done.connect(lambda r: results.append(r))
    th = MonitorThread(worker)
    th.start()
    try:
        w.show()
        assert _wait(lambda: len(results) >= 1)
        w.close()
        QCoreApplication.processEvents()
        assert not w.isVisible(), "окно должно свернуться в трей"
        n = len(results)
        assert _wait(lambda: len(results) > n, timeout=4), "мониторинг должен продолжаться в трее"
        assert th.is_running()
    finally:
        th.shutdown()
        w.allow_quit()
        w.close()
        st.close()
    assert not th.is_running()


def test_pause_stops_cycles(qapp):
    from app.monitor_worker import MonitorThread, MonitorWorker
    from tests.fakes import make_detector

    worker = MonitorWorker(make_detector(), interval_s=1)
    results = []
    worker.cycle_done.connect(lambda r: results.append(r))
    th = MonitorThread(worker)
    th.start()
    try:
        assert _wait(lambda: len(results) >= 1)
        from PySide6.QtCore import QMetaObject, Qt, Q_ARG
        QMetaObject.invokeMethod(worker, "set_paused", Qt.BlockingQueuedConnection, Q_ARG(bool, True))
        n = len(results)
        time.sleep(1.6)
        QCoreApplication.processEvents()
        assert len(results) == n
    finally:
        th.shutdown()


# ---------------------------------------------------------------- Scenario 7
def test_single_instance(qapp):
    from app.single_instance import SingleInstance

    name = f"rdpmon-test-{time.time_ns()}"
    first = SingleInstance(name)
    assert first.notify_existing() is False
    assert first.listen()
    got = []
    first.activated.connect(got.append)
    second = SingleInstance(name)
    assert second.notify_existing("show") is True
    assert _wait(lambda: got == ["show"])
    first.close()


def test_tray_icons_for_all_states(qapp):
    from core.models import OverallStatus
    from gui import theme
    for s in OverallStatus:
        assert not theme.status_icon(s).isNull()
