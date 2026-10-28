"""ТОЛЬКО ДЛЯ РАЗРАБОТКИ: рендер страниц интерфейса на тестовых данных (offscreen) в PNG.

В рабочем режиме приложение тестовые данные не использует. Запуск:
    QT_QPA_PLATFORM=offscreen python tools/render_preview.py out_dir
"""
from __future__ import annotations

import os
import sys
import tempfile
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("RDPMON_DATA_DIR", tempfile.mkdtemp())

from PySide6.QtWidgets import QApplication  # noqa: E402

from app.config import Settings  # noqa: E402
from core.diagnostics import run_diagnostics  # noqa: E402
from core.eventlog_monitor import LSM_CHANNEL, RCM_CHANNEL, SECURITY_CHANNEL  # noqa: E402
from core.models import SessionState  # noqa: E402
from gui import theme  # noqa: E402
from gui.main_window import MainWindow  # noqa: E402
from services.storage import Storage  # noqa: E402
from tests.fakes import T0, FakeLogs, FakeWts, console, make_detector, raw, rdp  # noqa: E402


def main(out: str) -> None:
    Path(out).mkdir(parents=True, exist_ok=True)
    app = QApplication([])
    app.setStyle("Fusion")
    app.setFont(theme.app_font())
    app.setStyleSheet(theme.QSS)
    st = Storage(Path(os.environ["RDPMON_DATA_DIR"]) / "h.db")
    logs = FakeLogs({
        LSM_CHANNEL: [raw(LSM_CHANNEL, 21, 1, T0 - timedelta(days=1, hours=2), User="ALIF\\it-admin", SessionID=3,
                          Address="10.10.4.21"),
                      raw(LSM_CHANNEL, 24, 2, T0 - timedelta(days=1, hours=1), User="ALIF\\it-admin", SessionID=3,
                          Address="10.10.4.21")],
        RCM_CHANNEL: [raw(RCM_CHANNEL, 1149, 3, T0 - timedelta(hours=5), Param1="test", Param2="", Param3="10.10.9.9")],
    }, denied={SECURITY_CHANNEL})
    wts = FakeWts([console()])
    det = make_detector(wts=wts, logs=logs, storage=st,
                        procs=lambda: [(4321, "AnyDesk.exe", "ALIF\\aziz"), (880, "CmRcService.exe", None)])
    det.run_cycle()
    wts.sessions = [console(state=SessionState.ACTIVE), rdp(sid=2, user="it-admin", ip="10.10.4.21")]
    r = det.run_cycle()
    win = MainWindow(Settings().validate(), st, os.environ["RDPMON_DATA_DIR"], "app.log", tray_available=True)
    win.resize(1280, 860)
    win.update_cycle(r)
    win.diagnostics.set_items(run_diagnostics(det, True, True, r.timestamp))
    win.show()
    import time
    end = time.time() + 0.8  # дождаться окончания анимации карточки статуса
    while time.time() < end:
        app.processEvents()
        time.sleep(0.02)
    for key in ("dashboard", "sessions", "history", "tools", "diagnostics", "settings"):
        win.show_page(key)
        app.processEvents()
        win.grab().save(str(Path(out) / f"{key}.png"))
    print("saved to", out)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "preview")
