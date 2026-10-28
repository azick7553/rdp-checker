"""Корреляция событий из разных источников и расчёт уровня достоверности.

Правила:
  * 1149 (RDP-аутентификация) сам по себе — «Низкая». Если в окне ±3 мин есть вход в сеанс
    (LSM 21/22/25, Security 4624 тип 10, 4778 или новый RDP-сеанс по WTS) того же пользователя
    или с того же IP — повышается до «Высокая».
  * Вход в RDP-сеанс, подтверждённый двумя разными источниками (например, LSM 21 + WTS API) —
    «Подтверждено».
  * Выход (LSM 23 / 4647) для сеанса, который ранее был удалённым, переклассифицируется
    в завершение RDP-сеанса.
  * TCP-соединение с RDP-портом, совпавшее по IP со входом в сеанс — «Высокая».
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from core.models import Confidence, ConnectionEvent, EventType

WINDOW = timedelta(minutes=3)

SESSION_ENTRY = {
    EventType.RDP_CONNECT, EventType.RDP_RECONNECT, EventType.RDP_SHELL_START, EventType.RDP_ACTIVE_AT_START,
}


@dataclass
class Upgrade:
    key: str
    confidence: Confidence
    note: str
    event_type: Optional[EventType] = None


def _source_family(ev: ConnectionEvent) -> str:
    s = ev.source.lower()
    if "lsm" in s:
        return "lsm"
    if "security" in s:
        return "security"
    if "rcm" in s:
        return "rcm"
    if "tcp" in s:
        return "tcp"
    if "процесс" in s:
        return "procs"
    return "wts"


def _related(a: ConnectionEvent, b: ConnectionEvent) -> bool:
    if abs(a.timestamp - b.timestamp) > WINDOW:
        return False
    if a.norm_user and b.norm_user and a.norm_user == b.norm_user:
        return True
    if a.ip and b.ip and a.ip == b.ip:
        return True
    return False


class Correlator:
    def __init__(self, maxlen: int = 2000) -> None:
        self._buf: deque[ConnectionEvent] = deque(maxlen=maxlen)
        self._remote_sessions: dict[int, ConnectionEvent] = {}
        self._remote_users: set[str] = set()

    def process(self, events: list[ConnectionEvent]) -> list[Upgrade]:
        upgrades: list[Upgrade] = []
        for ev in sorted(events, key=lambda e: e.timestamp):
            upgrades.extend(self._process_one(ev))
            self._buf.append(ev)
        return upgrades

    def _process_one(self, ev: ConnectionEvent) -> list[Upgrade]:
        ups: list[Upgrade] = []
        t = ev.event_type

        if t == EventType.RDP_AUTH:
            entry = self._find(ev, SESSION_ENTRY)
            if entry:
                ev.confidence = Confidence.HIGH
                ev.details += f" Вход в сеанс подтверждён: {entry.type_label} ({entry.source})."

        elif t in SESSION_ENTRY:
            if ev.session_id is not None:
                self._remote_sessions[ev.session_id] = ev
            if ev.norm_user:
                self._remote_users.add(ev.norm_user)
            for other in self._related_all(ev):
                if other.event_type == EventType.RDP_AUTH and other.confidence < Confidence.HIGH:
                    other.confidence = Confidence.HIGH
                    note = f" Вход в сеанс подтверждён: {ev.type_label} ({ev.source})."
                    other.details += note
                    ups.append(Upgrade(other.key, Confidence.HIGH, note))
                elif other.event_type == EventType.NETWORK_CONNECT and other.confidence < Confidence.HIGH and other.ip == ev.ip:
                    other.confidence = Confidence.HIGH
                    note = f" Совпадает со входом в RDP-сеанс ({ev.source})."
                    other.details += note
                    ups.append(Upgrade(other.key, Confidence.HIGH, note))
                elif (other.event_type in SESSION_ENTRY and _source_family(other) != _source_family(ev)
                      and other.confidence >= Confidence.HIGH):
                    if ev.confidence < Confidence.CONFIRMED:
                        ev.confidence = Confidence.CONFIRMED
                        ev.details += f" Подтверждено источником: {other.source}."
                    if other.confidence < Confidence.CONFIRMED:
                        other.confidence = Confidence.CONFIRMED
                        note = f" Подтверждено источником: {ev.source}."
                        other.details += note
                        ups.append(Upgrade(other.key, Confidence.CONFIRMED, note))
                if not ev.ip and other.ip:
                    ev.ip = other.ip

        elif t == EventType.NETWORK_CONNECT:
            entry = self._find(ev, SESSION_ENTRY, require_ip=True)
            if entry:
                ev.confidence = max(ev.confidence, Confidence.HIGH)
                ev.details += f" Совпадает со входом в RDP-сеанс ({entry.source})."

        elif t == EventType.LOCAL_LOGOFF:
            prev = self._remote_sessions.get(ev.session_id) if ev.session_id is not None else None
            if prev is not None and (not ev.norm_user or not prev.norm_user or ev.norm_user == prev.norm_user):
                ev.event_type = EventType.RDP_LOGOFF
                ev.confidence = Confidence.HIGH
                ev.ip = ev.ip or prev.ip
                ev.details += " Сеанс ранее был удалённым (RDP)."
                self._remote_sessions.pop(ev.session_id, None)

        elif t == EventType.RDP_LOGOFF and ev.session_id is not None:
            self._remote_sessions.pop(ev.session_id, None)

        elif t == EventType.SHADOW_START:
            for other in self._buf:
                if other.event_type == EventType.SHADOW_SUSPECTED and abs(other.timestamp - ev.timestamp) <= WINDOW \
                        and other.confidence < Confidence.HIGH:
                    other.confidence = Confidence.HIGH
                    note = f" Подтверждено журналом: {ev.source}."
                    other.details += note
                    ups.append(Upgrade(other.key, Confidence.HIGH, note))

        elif t == EventType.SHADOW_SUSPECTED:
            for other in self._buf:
                if other.event_type == EventType.SHADOW_START and abs(other.timestamp - ev.timestamp) <= WINDOW:
                    ev.confidence = Confidence.HIGH
                    ev.details += f" Подтверждено журналом: {other.source}."
                    break
        return ups

    def _find(self, ev: ConnectionEvent, types: set[EventType], require_ip: bool = False) -> Optional[ConnectionEvent]:
        for other in reversed(self._buf):
            if other.event_type not in types:
                continue
            if require_ip:
                if ev.ip and other.ip == ev.ip and abs(other.timestamp - ev.timestamp) <= WINDOW:
                    return other
            elif _related(ev, other):
                return other
        return None

    def _related_all(self, ev: ConnectionEvent) -> list[ConnectionEvent]:
        out = []
        for other in self._buf:
            if other is ev:
                continue
            if _related(ev, other):
                out.append(other)
            elif (other.event_type == EventType.NETWORK_CONNECT and ev.ip and other.ip == ev.ip
                  and abs(other.timestamp - ev.timestamp) <= WINDOW):
                out.append(other)
        return out
