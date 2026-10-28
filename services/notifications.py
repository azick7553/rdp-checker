"""Уведомления: фильтрация по категориям, подавление повторов и текст сообщений.

Показ уведомления (трей Windows) и звук передаются как функции-бэкенды,
поэтому логику можно тестировать без GUI.
"""
from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Optional

from core.models import Confidence, ConnectionEvent, EventType

log = logging.getLogger(__name__)

CATEGORY = {
    EventType.RDP_CONNECT: "connect",
    EventType.RDP_ACTIVE_AT_START: "connect",
    EventType.RDP_SHELL_START: "connect",
    EventType.RDP_RECONNECT: "reconnect",
    EventType.RDP_DISCONNECT: "disconnect",
    EventType.RDP_LOGOFF: "logoff",
    EventType.RDP_STATE_CHANGE: "state",
    EventType.RDP_AUTH: "auth",
    EventType.SHADOW_START: "shadow",
    EventType.SHADOW_STOP: "shadow",
    EventType.SHADOW_PERMISSION: "shadow",
    EventType.SHADOW_SUSPECTED: "shadow",
    EventType.NETWORK_CONNECT: "network",
    EventType.REMOTE_TOOL_STARTED: "remote_tools",
    EventType.REMOTE_TOOL_INCOMING: "remote_tools",
    EventType.MISSED_WHILE_AWAY: "away",
}

# Семейства для объединения уведомлений об одном и том же инциденте из разных источников
FAMILY = {
    "connect": "entry", "reconnect": "entry", "auth": "entry", "network": "entry",
    "disconnect": "exit", "logoff": "exit", "state": "state", "shadow": "shadow",
    "remote_tools": "tools", "away": "away",
}

TYPE_PRIORITY = {
    EventType.RDP_ACTIVE_AT_START: 0, EventType.RDP_CONNECT: 0, EventType.SHADOW_START: 0,
    EventType.RDP_RECONNECT: 1, EventType.RDP_SHELL_START: 2, EventType.SHADOW_SUSPECTED: 2,
    EventType.RDP_AUTH: 3, EventType.NETWORK_CONNECT: 4,
}

SEVERITY_CRITICAL, SEVERITY_WARNING, SEVERITY_INFO = "critical", "warning", "info"

DEDUP_WINDOW = timedelta(seconds=90)


@dataclass
class Notification:
    title: str
    body: str
    severity: str
    event: ConnectionEvent


def _fmt_time(ev: ConnectionEvent) -> str:
    today = datetime.now().astimezone().date()
    return ev.timestamp.strftime("%H:%M:%S" if ev.timestamp.date() == today else "%d.%m.%Y %H:%M:%S")


def format_notification(ev: ConnectionEvent) -> Notification:
    t = ev.event_type
    user = ev.user or "Недоступен"
    ip = ev.ip or "Недоступен"
    when = _fmt_time(ev)
    lines: list[str]
    if t in (EventType.RDP_CONNECT, EventType.RDP_ACTIVE_AT_START, EventType.RDP_SHELL_START):
        title, sev = "Внимание! RDP-подключение", SEVERITY_CRITICAL
        lead = ("Обнаружена активная удалённая сессия." if t == EventType.RDP_ACTIVE_AT_START
                else "Обнаружена новая удалённая сессия.")
    elif t == EventType.RDP_RECONNECT:
        title, sev, lead = "Внимание! Повторное RDP-подключение", SEVERITY_CRITICAL, "Удалённый пользователь снова подключился к сеансу."
    elif t == EventType.RDP_DISCONNECT:
        title, sev, lead = "RDP: удалённый пользователь отключился", SEVERITY_INFO, "Удалённый клиент отключился от сеанса."
    elif t == EventType.RDP_LOGOFF:
        title, sev, lead = "RDP-сеанс завершён", SEVERITY_INFO, "Удалённый сеанс завершён."
    elif t == EventType.RDP_STATE_CHANGE:
        title, sev, lead = "RDP: изменение состояния сеанса", SEVERITY_WARNING, ev.details.split(". ")[0] + "."
    elif t == EventType.RDP_AUTH:
        title, sev = "RDP-аутентификация", SEVERITY_WARNING
        lead = ("Успешная аутентификация RDP." + (" Вход в сеанс подтверждён." if ev.confidence >= Confidence.HIGH
                                                 else " Вход в рабочий стол не подтверждён."))
    elif t in (EventType.SHADOW_START, EventType.SHADOW_SUSPECTED, EventType.SHADOW_PERMISSION):
        title, sev = "Внимание! Теневое подключение", SEVERITY_CRITICAL
        lead = ("Обнаружены признаки просмотра или управления вашим сеансом (RDP Shadow)."
                if t == EventType.SHADOW_SUSPECTED else "Зарегистрировано теневое подключение к сеансу (RDP Shadow).")
    elif t == EventType.SHADOW_STOP:
        title, sev, lead = "Теневое подключение завершено", SEVERITY_INFO, "Просмотр/управление сеансом прекращено."
    elif t == EventType.NETWORK_CONNECT:
        title, sev, lead = "Соединение с RDP-портом", SEVERITY_WARNING, "Удалённый компьютер установил соединение с RDP-портом."
    elif t == EventType.REMOTE_TOOL_INCOMING:
        title, sev, lead = "Входящее подключение (удалённый доступ)", SEVERITY_WARNING, ev.details
    elif t == EventType.REMOTE_TOOL_STARTED:
        title, sev, lead = "Запущено средство удалённого доступа", SEVERITY_INFO, ev.details
    elif t == EventType.MISSED_WHILE_AWAY:
        title, sev, lead = "Пока ваш сеанс был отключён", SEVERITY_WARNING, ev.details
        return Notification(title, lead[:350], sev, ev)
    else:
        title, sev, lead = ev.type_label, SEVERITY_INFO, ev.details
    lines = [lead, "", f"Пользователь: {user}", f"IP: {ip}"]
    if ev.session_id is not None:
        lines.append(f"Сеанс: {ev.session_id}")
    lines.append(f"Время: {when}")
    lines.append(f"Достоверность: {ev.confidence.label}")
    return Notification(title, "\n".join(lines), sev, ev)


def play_sound(choice: str, custom_path: str = "", severity: str = SEVERITY_WARNING,
               fallback: Optional[Callable[[], None]] = None) -> None:
    if choice == "none":
        return
    if sys.platform == "win32":
        try:
            import winsound
            if choice == "custom" and custom_path:
                winsound.PlaySound(custom_path, winsound.SND_FILENAME | winsound.SND_ASYNC | winsound.SND_NODEFAULT)
                return
            flag = {
                "default": winsound.MB_OK,
                "warning": winsound.MB_ICONEXCLAMATION,
                "critical": winsound.MB_ICONHAND,
            }.get(choice, winsound.MB_ICONEXCLAMATION)
            winsound.MessageBeep(flag)
            return
        except Exception as e:  # noqa: BLE001
            log.debug("winsound failed: %s", e)
    if fallback:
        fallback()


class NotificationService:
    def __init__(self, settings, show_func: Callable[[Notification], None],
                 sound_func: Optional[Callable[[Notification], None]] = None,
                 clock: Optional[Callable[[], datetime]] = None) -> None:
        self.settings = settings
        self._show = show_func
        self._sound = sound_func
        self._clock = clock or (lambda: datetime.now().astimezone())
        self._sent_keys: set[str] = set()
        self._recent: list[tuple[datetime, str, Confidence, ConnectionEvent]] = []

    def category_enabled(self, ev: ConnectionEvent) -> bool:
        cat = CATEGORY.get(ev.event_type)
        if cat is None:
            return False
        return bool(self.settings.notifications_enabled and self.settings.notify.get(cat, True))

    def _is_duplicate(self, ev: ConnectionEvent, now: datetime) -> bool:
        if ev.key and ev.key in self._sent_keys:
            return True
        fam = FAMILY.get(CATEGORY.get(ev.event_type, ""), "")
        self._recent = [r for r in self._recent if now - r[0] <= DEDUP_WINDOW]
        for ts, f, conf, other in self._recent:
            if f != fam:
                continue
            if ev.ip and other.ip and ev.ip != other.ip:
                continue  # разные клиенты — разные инциденты
            if ev.norm_user and other.norm_user and ev.norm_user != other.norm_user:
                continue
            if (ev.session_id is not None and other.session_id is not None and ev.session_id != other.session_id
                    and fam != "entry"):
                continue
            if conf >= ev.confidence:
                return True
        return False

    def handle(self, events: list[ConnectionEvent]) -> list[Notification]:
        now = self._clock()
        shown: list[Notification] = []
        ordered = sorted(events, key=lambda e: (-int(e.confidence), TYPE_PRIORITY.get(e.event_type, 5)))
        for ev in ordered:
            if not self.category_enabled(ev):
                continue
            if self._is_duplicate(ev, now):
                if ev.key:
                    self._sent_keys.add(ev.key)
                continue
            n = format_notification(ev)
            try:
                self._show(n)
            except Exception as e:  # noqa: BLE001
                log.warning("Notification failed: %s", e)
            if self._sound and (n.severity != SEVERITY_INFO or self.settings.sound_on_disconnect):
                try:
                    self._sound(n)
                except Exception as e:  # noqa: BLE001
                    log.debug("Sound failed: %s", e)
            if ev.key:
                self._sent_keys.add(ev.key)
            self._recent.append((now, FAMILY.get(CATEGORY.get(ev.event_type, ""), ""), ev.confidence, ev))
            shown.append(n)
        if len(self._sent_keys) > 5000:
            self._sent_keys = set(list(self._sent_keys)[-2000:])
        return shown
