"""Настройки приложения и пути к пользовательским данным (без прав администратора)."""
from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

APP_NAME = "RDP Connection Monitor"
APP_ID = "RDPConnectionMonitor"
APP_VERSION = "1.0.0"

log = logging.getLogger(__name__)


def resource_path(relative: str) -> Path:
    """Путь к ресурсу и при запуске из исходников, и внутри PyInstaller-EXE (sys._MEIPASS)."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return base / relative


def data_dir() -> Path:
    """%LOCALAPPDATA%\\RDPConnectionMonitor (на других ОС — ~/.local/share/RDPConnectionMonitor)."""
    override = os.environ.get("RDPMON_DATA_DIR")
    if override:
        base = Path(override)
    elif sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / APP_ID
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / APP_ID
    base.mkdir(parents=True, exist_ok=True)
    return base


NOTIFY_CATEGORIES = {
    "connect": "Новое RDP-подключение",
    "reconnect": "Повторное подключение",
    "disconnect": "Отключение удалённого пользователя",
    "logoff": "Завершение RDP-сеанса",
    "state": "Изменение состояния сеанса",
    "auth": "RDP-аутентификация без подтверждённого входа (1149)",
    "shadow": "Теневое подключение (Shadow)",
    "network": "TCP-соединение с RDP-портом",
    "remote_tools": "Средства удалённого доступа (AnyDesk, TeamViewer и др.)",
    "away": "Сводка событий, пока сеанс был отключён",
}

SOUND_CHOICES = {
    "none": "Без звука",
    "default": "Системный звук",
    "warning": "Предупреждение",
    "critical": "Критическая ошибка",
    "custom": "Свой WAV-файл",
}


@dataclass
class Settings:
    poll_interval: int = 2                    # секунды, 1–30
    retention_days: int = 30
    eventlog_lookback_days: int = 7
    minimize_to_tray: bool = True
    start_minimized: bool = False
    notifications_enabled: bool = True
    notify: dict = field(default_factory=lambda: {k: True for k in NOTIFY_CATEGORIES} | {"state": False})
    sound: str = "warning"
    sound_on_disconnect: bool = False
    custom_sound_path: str = ""
    read_security_log: bool = True
    remote_tools_enabled: bool = True
    show_local_sessions: bool = True

    def validate(self) -> "Settings":
        self.poll_interval = max(1, min(30, int(self.poll_interval)))
        self.retention_days = max(1, min(3650, int(self.retention_days)))
        self.eventlog_lookback_days = max(1, min(90, int(self.eventlog_lookback_days)))
        if self.sound not in SOUND_CHOICES:
            self.sound = "warning"
        notify = {k: True for k in NOTIFY_CATEGORIES} | {"state": False}
        if isinstance(self.notify, dict):
            notify.update({k: bool(v) for k, v in self.notify.items() if k in NOTIFY_CATEGORIES})
        self.notify = notify
        return self

    @classmethod
    def path(cls) -> Path:
        return data_dir() / "settings.json"

    @classmethod
    def load(cls) -> "Settings":
        p = cls.path()
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            known = {f.name for f in fields(cls)}
            return cls(**{k: v for k, v in raw.items() if k in known}).validate()
        except FileNotFoundError:
            return cls().validate()
        except Exception as e:  # noqa: BLE001
            log.warning("Settings file is broken, using defaults: %s", e)
            return cls().validate()

    def save(self) -> None:
        self.validate()
        p = self.path()
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self), ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(p)
