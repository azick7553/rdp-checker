"""Сравнение предыдущего и текущего списка сеансов → события подключения/отключения."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from core.models import (
    SESSION_STATE_RU, Confidence, ConnectionEvent, EventType, SessionInfo, SessionState,
)

SOURCE = "WTS API"


def _ident(s: SessionInfo) -> str:
    """Идентичность сеанса: один и тот же ID может быть переиспользован Windows."""
    t = s.logon_time or s.first_seen
    return f"{t.timestamp():.0f}" if t else "?"


def _fmt_time(t: Optional[datetime]) -> str:
    return t.strftime("%d.%m.%Y %H:%M:%S") if t else "неизвестно"


class SessionManager:
    def __init__(self) -> None:
        self._prev: dict[int, SessionInfo] = {}
        self._initialized = False

    @property
    def initialized(self) -> bool:
        return self._initialized

    def reset(self) -> None:
        self._prev.clear()
        self._initialized = False

    def _event(self, now: datetime, etype: EventType, s: SessionInfo, conf: Confidence, details: str) -> ConnectionEvent:
        return ConnectionEvent(
            timestamp=now,
            event_type=etype,
            source=s.source or SOURCE,
            confidence=conf,
            user=s.full_user,
            ip=s.client_ip,
            session_id=s.session_id,
            client_name=s.client_name,
            details=details,
            key=f"wts:{s.session_id}:{_ident(s)}:{etype.value}:{s.state.value}:{now.timestamp():.0f}"
            if etype != EventType.RDP_ACTIVE_AT_START
            else f"wts:{s.session_id}:{_ident(s)}:{etype.value}",
        )

    @staticmethod
    def _describe(s: SessionInfo) -> str:
        parts = [f"Станция: {s.winstation or '—'}", f"Состояние: {SESSION_STATE_RU.get(s.state, s.state.value)}"]
        if s.client_name:
            parts.append(f"Клиент: {s.client_name}")
        if s.connect_time:
            parts.append(f"Подключён: {_fmt_time(s.connect_time)}")
        if s.logon_time:
            parts.append(f"Вход: {_fmt_time(s.logon_time)}")
        return "; ".join(parts)

    def update(self, sessions: list[SessionInfo], now: Optional[datetime] = None) -> list[ConnectionEvent]:
        now = now or datetime.now().astimezone()
        events: list[ConnectionEvent] = []
        current = {s.session_id: s for s in sessions if not s.is_listener and not s.is_services}
        first_run = not self._initialized

        for sid, s in current.items():
            prev = self._prev.get(sid)
            if prev is not None and _ident(prev) != _ident(s) and prev.logon_time and s.logon_time:
                # ID переиспользован — старый сеанс завершился, начался новый
                events.extend(self._vanished(prev, now))
                prev = None

            if prev is None:
                events.extend(self._appeared(s, now, first_run))
            else:
                events.extend(self._changed(prev, s, now))

        for sid, prev in self._prev.items():
            if sid not in current:
                events.extend(self._vanished(prev, now))

        self._prev = current
        self._initialized = True
        return events

    # ------------------------------------------------------------------ cases
    def _appeared(self, s: SessionInfo, now: datetime, first_run: bool) -> list[ConnectionEvent]:
        if s.is_remote_live:
            conf = Confidence.CONFIRMED if s.user else Confidence.HIGH
            extra = "" if s.user else " Пользователь ещё не выполнил вход (экран входа RDP)."
            if first_run:
                return [self._event(now, EventType.RDP_ACTIVE_AT_START, s, conf,
                                    "RDP-сеанс уже был активен при запуске монитора. " + self._describe(s) + extra)]
            return [self._event(now, EventType.RDP_CONNECT, s, conf, "Новый RDP-сеанс. " + self._describe(s) + extra)]
        if s.is_remote:
            # RDP-сеанс существует, но клиент отключён
            if first_run:
                return [self._event(now, EventType.RDP_STATE_CHANGE, s, Confidence.INFO,
                                    "При запуске найден отключённый RDP-сеанс. " + self._describe(s))]
            return [self._event(now, EventType.RDP_STATE_CHANGE, s, Confidence.MEDIUM,
                                "Появился отключённый RDP-сеанс. " + self._describe(s))]
        if not first_run and s.user:
            return [self._event(now, EventType.LOCAL_LOGON, s, Confidence.INFO, "Локальный сеанс. " + self._describe(s))]
        return []

    def _changed(self, prev: SessionInfo, s: SessionInfo, now: datetime) -> list[ConnectionEvent]:
        was, is_ = prev.is_remote_live, s.is_remote_live
        if not was and is_:
            if prev.state == SessionState.DISCONNECTED or (prev.is_remote and not prev.is_remote_live):
                return [self._event(now, EventType.RDP_RECONNECT, s, Confidence.CONFIRMED,
                                    "Повторное подключение к существующему сеансу. " + self._describe(s))]
            if not prev.is_remote:
                return [self._event(now, EventType.RDP_CONNECT, s, Confidence.CONFIRMED,
                                    "Существующий локальный сеанс подключён удалённо по RDP. " + self._describe(s))]
            return [self._event(now, EventType.RDP_CONNECT, s, Confidence.CONFIRMED, self._describe(s))]
        if was and not is_:
            if s.state == SessionState.DISCONNECTED:
                ev = self._event(now, EventType.RDP_DISCONNECT, prev, Confidence.CONFIRMED,
                                 "Удалённый клиент отключился, сеанс сохранён. " + self._describe(s))
                ev.session_id = s.session_id
                return [ev]
            if not s.is_remote:
                return [self._event(now, EventType.RDP_DISCONNECT, prev, Confidence.CONFIRMED,
                                    "Сеанс возвращён на локальную консоль. " + self._describe(s))]
            return [self._event(now, EventType.RDP_STATE_CHANGE, s, Confidence.HIGH,
                                f"{SESSION_STATE_RU.get(prev.state)} → {SESSION_STATE_RU.get(s.state)}. " + self._describe(s))]
        if was and is_:
            out = []
            if prev.client_ip and s.client_ip and prev.client_ip != s.client_ip:
                out.append(self._event(now, EventType.RDP_RECONNECT, s, Confidence.CONFIRMED,
                                       f"К сеансу подключился другой клиент: {prev.client_ip} → {s.client_ip}. " + self._describe(s)))
            elif not prev.user and s.user:
                out.append(self._event(now, EventType.RDP_STATE_CHANGE, s, Confidence.CONFIRMED,
                                       f"На экране входа RDP выполнен вход: {s.full_user}. " + self._describe(s)))
            elif prev.state != s.state:
                out.append(self._event(now, EventType.RDP_STATE_CHANGE, s, Confidence.INFO,
                                       f"{SESSION_STATE_RU.get(prev.state)} → {SESSION_STATE_RU.get(s.state)}. " + self._describe(s)))
            return out
        if s.is_remote and prev.state != s.state:
            return [self._event(now, EventType.RDP_STATE_CHANGE, s, Confidence.INFO,
                                f"{SESSION_STATE_RU.get(prev.state)} → {SESSION_STATE_RU.get(s.state)}. " + self._describe(s))]
        return []

    def _vanished(self, prev: SessionInfo, now: datetime) -> list[ConnectionEvent]:
        if prev.is_remote:
            return [self._event(now, EventType.RDP_LOGOFF, prev, Confidence.CONFIRMED,
                                "RDP-сеанс завершён (выход из системы). " + self._describe(prev))]
        if prev.user:
            return [self._event(now, EventType.LOCAL_LOGOFF, prev, Confidence.INFO, "Сеанс завершён. " + self._describe(prev))]
        return []
