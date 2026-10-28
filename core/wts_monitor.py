"""Получение списка сеансов через Windows Terminal Services API.

Основной источник — WTSEnumerateSessionsW + WTSQuerySessionInformationW.
Резервный источник — утилита `query user` (quser.exe), если WTS API недоступен.

Обычному пользователю перечисление сеансов разрешено правом «Query Information»
в стандартных разрешениях слушателя RDP-Tcp. На управляемых компьютерах эти
разрешения могут быть изменены — тогда источник помечается как недоступный.
"""
from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from core import winapi
from core.models import Protocol, SessionInfo, SessionState, SourceState, SourceStatus

log = logging.getLogger(__name__)


@dataclass
class WtsSnapshot:
    sessions: list[SessionInfo]
    status: SourceStatus
    current_session_id: Optional[int] = None
    console_session_id: Optional[int] = None
    current_is_remote: bool = False
    current_is_remote_controlled: bool = False
    listener_present: bool = False
    used_fallback: bool = False
    errors: list[str] = field(default_factory=list)


class WtsMonitor:
    """Опрос сеансов. Не хранит состояние между вызовами (кроме кеша first_seen)."""

    def __init__(self) -> None:
        self._first_seen: dict[tuple[int, str], datetime] = {}

    # ------------------------------------------------------------------ helpers
    def _first_seen_for(self, sid: int, winstation: str, user: str) -> datetime:
        key = (sid, f"{winstation}|{user}".lower())
        if key not in self._first_seen:
            self._first_seen[key] = datetime.now().astimezone()
        return self._first_seen[key]

    @staticmethod
    def _protocol(code: int) -> Protocol:
        return {0: Protocol.CONSOLE, 1: Protocol.ICA, 2: Protocol.RDP}.get(code, Protocol.UNKNOWN)

    # ------------------------------------------------------------------ main
    def snapshot(self) -> WtsSnapshot:
        if not winapi.IS_WINDOWS:
            return WtsSnapshot(
                [], SourceStatus("wts", "WTS API", SourceState.ERROR, "Доступно только в Windows"),
            )
        errors: list[str] = []
        current_sid = console_sid = None
        cur_remote = cur_controlled = False
        try:
            current_sid = winapi.current_session_id()
        except Exception as e:  # pragma: no cover
            errors.append(f"ProcessIdToSessionId: {e}")
        try:
            console_sid = winapi.active_console_session_id()
        except Exception as e:  # pragma: no cover
            errors.append(f"WTSGetActiveConsoleSessionId: {e}")
        try:
            cur_remote = winapi.is_remote_session()
            cur_controlled = winapi.is_remote_controlled()
        except Exception as e:  # pragma: no cover
            errors.append(f"GetSystemMetrics: {e}")

        try:
            raw = winapi.wts_enumerate_sessions()
        except winapi.WinApiError as e:  # pragma: no cover - Windows only
            log.warning("WTSEnumerateSessions failed: %s", e)
            snap = self._fallback_quser(current_sid)
            snap.current_session_id = current_sid
            snap.console_session_id = console_sid
            snap.current_is_remote = cur_remote
            snap.current_is_remote_controlled = cur_controlled
            snap.errors = errors + [str(e)]
            if not snap.status.usable:
                state = SourceState.DENIED if e.access_denied else SourceState.ERROR
                snap.status = SourceStatus(
                    "wts", "WTS API", state,
                    "Windows запретила перечисление сеансов для этой учётной записи"
                    if e.access_denied else f"Ошибка WTS API: {e}",
                )
            return snap

        sessions: list[SessionInfo] = []
        partial = False
        listener = False
        for sid, winstation, state_code in raw:
            state = SessionState.from_wts(state_code)
            s = SessionInfo(session_id=sid, winstation=winstation, state=state)
            if s.is_listener:
                if winstation.lower().startswith("rdp"):
                    listener = True
                continue
            s.is_current = sid == current_sid
            s.is_console = sid == console_sid
            for info_class, attr in (
                (winapi.WTSUserName, "user"),
                (winapi.WTSDomainName, "domain"),
                (winapi.WTSClientName, "client_name"),
            ):
                try:
                    setattr(s, attr, winapi.wts_query_string(sid, info_class))
                except Exception as e:  # pragma: no cover
                    s.query_errors.append(f"{attr}: {e}")
            try:
                s.protocol = self._protocol(winapi.wts_query_protocol(sid))
            except Exception as e:  # pragma: no cover
                s.query_errors.append(f"protocol: {e}")
            try:
                s.client_ip = winapi.wts_query_client_address(sid)
            except Exception as e:  # pragma: no cover
                s.query_errors.append(f"client_ip: {e}")
            try:
                info = winapi.wts_query_session_info(sid)
                s.connect_time = info.get("connect_time")
                s.logon_time = info.get("logon_time")
                s.disconnect_time = info.get("disconnect_time")
                if not s.user and info.get("user"):
                    s.user = info["user"]
                    s.domain = s.domain or info.get("domain", "")
            except Exception as e:  # pragma: no cover
                s.query_errors.append(f"session_info: {e}")
            if s.is_current and cur_remote and s.protocol == Protocol.UNKNOWN:
                s.protocol = Protocol.RDP
            if s.query_errors and not s.is_services:
                partial = True
            s.first_seen = self._first_seen_for(sid, winstation, s.user)
            sessions.append(s)

        if partial:
            status = SourceStatus(
                "wts", "WTS API", SourceState.PARTIAL,
                "Сеансы перечислены, но часть сведений о некоторых сеансах недоступна",
                "; ".join(f"#{s.session_id}: {', '.join(s.query_errors)}" for s in sessions if s.query_errors),
            )
        else:
            status = SourceStatus("wts", "WTS API", SourceState.AVAILABLE, f"Сеансов: {len(sessions)}")
        return WtsSnapshot(
            sessions, status, current_sid, console_sid, cur_remote, cur_controlled, listener, False, errors,
        )

    # ------------------------------------------------------------------ fallback
    def _fallback_quser(self, current_sid: Optional[int]) -> WtsSnapshot:  # pragma: no cover - Windows only
        try:
            out = run_hidden(["query", "user"], timeout=6)
        except Exception as e:
            return WtsSnapshot([], SourceStatus("wts", "WTS API", SourceState.ERROR, f"query user: {e}"), used_fallback=True)
        sessions = parse_quser(out)
        for s in sessions:
            s.is_current = s.session_id == current_sid
            s.first_seen = self._first_seen_for(s.session_id, s.winstation, s.user)
        return WtsSnapshot(
            sessions,
            SourceStatus(
                "wts", "WTS API", SourceState.PARTIAL,
                "WTS API недоступен, используется резервный источник «query user» (без IP-адресов)",
            ),
            used_fallback=True,
        )


def run_hidden(args: list[str], timeout: float = 5.0) -> str:
    """Запуск консольной утилиты без мигания окна. Вывод декодируется с учётом OEM-кодировки."""
    kwargs = {}
    if winapi.IS_WINDOWS:
        kwargs["creationflags"] = winapi.CREATE_NO_WINDOW
    proc = subprocess.run(args, capture_output=True, timeout=timeout, **kwargs)
    data = proc.stdout or proc.stderr or b""
    for enc in ("cp866", "utf-8", "cp1251"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


_STATE_WORDS = {
    "active": SessionState.ACTIVE, "активно": SessionState.ACTIVE, "активен": SessionState.ACTIVE,
    "активный": SessionState.ACTIVE, "актив": SessionState.ACTIVE,
    "disc": SessionState.DISCONNECTED, "диск": SessionState.DISCONNECTED,
    "disconnected": SessionState.DISCONNECTED, "отключено": SessionState.DISCONNECTED,
    "conn": SessionState.CONNECTED, "listen": SessionState.LISTEN,
}


def parse_quser(output: str) -> list[SessionInfo]:
    """Разбор вывода `query user` (английская и русская локализация).

    Пример строки: ">user01  rdp-tcp#3  2  Active  .  28.10.2026 14:32"
    Имя станции может отсутствовать у отключённых сеансов.
    """
    result: list[SessionInfo] = []
    lines = [ln for ln in output.splitlines() if ln.strip()]
    for line in lines[1:]:  # первая строка — заголовок
        current = line.startswith(">")
        tokens = line.lstrip(">").split()
        if len(tokens) < 3:
            continue
        # индекс первого числового токена — ID сеанса
        idx = next((i for i, t in enumerate(tokens[1:], start=1) if t.isdigit()), None)
        if idx is None or idx + 1 >= len(tokens):
            continue
        user = tokens[0]
        winstation = tokens[1] if idx == 2 else ""
        state = _STATE_WORDS.get(tokens[idx + 1].lower().rstrip("."), SessionState.UNKNOWN)
        s = SessionInfo(
            session_id=int(tokens[idx]), winstation=winstation, state=state, user=user,
            source="query user", is_current=current,
        )
        if winstation.lower().startswith("rdp-tcp#"):
            s.protocol = Protocol.RDP
        elif winstation.lower() == "console":
            s.protocol = Protocol.CONSOLE
        m = re.search(r"(\d{1,2}[./]\d{1,2}[./]\d{2,4})\s+(\d{1,2}:\d{2})", line)
        if m:
            for fmt in ("%d.%m.%Y %H:%M", "%m/%d/%Y %H:%M", "%d/%m/%Y %H:%M", "%d.%m.%y %H:%M"):
                try:
                    s.logon_time = datetime.strptime(f"{m.group(1)} {m.group(2)}", fmt).astimezone()
                    break
                except ValueError:
                    continue
        result.append(s)
    return result
