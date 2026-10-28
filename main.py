"""RDP Connection Monitor — точка входа.

    RDPConnectionMonitor.exe              — обычный запуск с окном и значком в трее
    RDPConnectionMonitor.exe --minimized  — запуск сразу в трей
    RDPConnectionMonitor.exe --probe      — без GUI: снимок источников в probe.json (для проверки на новом ПК)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Запуск из исходников: python main.py
sys.path.insert(0, str(Path(__file__).resolve().parent))


def probe() -> int:
    """Однократная проверка без GUI. Результат: %LOCALAPPDATA%\\RDPConnectionMonitor\\probe.json."""
    import time
    from dataclasses import asdict

    from app.config import data_dir
    from core.connection_detector import ConnectionDetector
    from core.diagnostics import diagnostics_report, items_to_dict, run_diagnostics

    det = ConnectionDetector()
    first = det.run_cycle(force=True)
    time.sleep(1)
    second = det.run_cycle(force=True)
    items = run_diagnostics(det)

    def enc(o):
        if hasattr(o, "isoformat"):
            return o.isoformat()
        if hasattr(o, "value"):
            return o.value
        return str(o)

    report = {
        "overall": second.overall.value,
        "title": second.overall_title,
        "reasons": second.overall_reasons,
        "sessions": [asdict(s) for s in second.sessions],
        "network": [asdict(c) for c in second.network],
        "remote_tools": [asdict(t) for t in second.remote_tools if t.installed or t.running],
        "sources": {k: asdict(v) for k, v in second.sources.items()},
        "events_loaded": len(first.new_events) + len(second.new_events),
        "recent_events": [asdict(e) for e in (first.new_events + second.new_events)[-30:]],
        "diagnostics": items_to_dict(items),
        "errors": first.errors + second.errors,
    }
    out = data_dir() / "probe.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=enc), encoding="utf-8")
    text = diagnostics_report(items) + f"\n\nСтатус: {second.overall_title}\nПолный отчёт: {out}\n"
    (data_dir() / "probe.txt").write_text(text, encoding="utf-8")
    if sys.stdout is not None:
        try:
            print(text)
        except UnicodeEncodeError:
            print(text.encode("ascii", "replace").decode())
    return 0


def main() -> int:
    if "--probe" in sys.argv:
        from services.logger import setup_logging
        setup_logging()
        return probe()
    from app.application import main as app_main
    return app_main(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
