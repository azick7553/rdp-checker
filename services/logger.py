"""Логирование ошибок в %LOCALAPPDATA%\\RDPConnectionMonitor\\logs."""
from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from app.config import data_dir

_configured = False


def log_dir() -> Path:
    d = data_dir() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def setup_logging(level: int = logging.INFO) -> Path:
    global _configured
    path = log_dir() / "app.log"
    if _configured:
        return path
    root = logging.getLogger()
    root.setLevel(level)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(threadName)s %(name)s: %(message)s")
    try:
        fh = RotatingFileHandler(path, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError:
        pass
    if sys.stderr is not None:  # в --windowed EXE stderr отсутствует
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(fmt)
        sh.setLevel(logging.WARNING)
        root.addHandler(sh)

    def _excepthook(exc_type, exc, tb):
        logging.getLogger("unhandled").critical("Unhandled exception", exc_info=(exc_type, exc, tb))

    sys.excepthook = _excepthook
    _configured = True
    return path
