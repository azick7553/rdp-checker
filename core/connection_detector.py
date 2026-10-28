"""Оркестратор: один цикл мониторинга = опрос всех источников, корреляция, сохранение, итоговый статус.

Класс не зависит от Qt и вызывается из фонового потока (см. app/monitor_worker.py).
Любая ошибка источника изолирована: цикл никогда не выбрасывает исключение наружу.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta
from typing import Optional, Protocol as TypingProtocol

from core.correlation import Correlator, Upgrade
from core.eventlog_monitor import EventLogMonitor
from core.models import (
    CONNECT_TYPES, DISCONNECT_TYPES, Confidence, ConnectionEvent, CycleResult, EventType, NetworkConnection,
    OverallStatus, RemoteToolStatus, SessionState, SourceState, SourceStatus,
)
from core.network_monitor import NetworkMonitor, RdpServerConfig, read_rdp_config
from core.remote_tools_detector import RemoteToolsDetector
from core.session_manager import SessionManager
from core.wts_monitor import WtsMonitor, WtsSnapshot

log = logging.getLogger(__name__)

NOTIFY_TYPES = CONNECT_TYPES | DISCONNECT_TYPES | {
    EventType.RDP_AUTH, EventType.SHADOW_SUSPECTED, EventType.SHADOW_PERMISSION, EventType.NETWORK_CONNECT,
    EventType.REMOTE_TOOL_INCOMING, EventType.REMOTE_TOOL_STARTED, EventType.RDP_STATE_CHANGE,
    EventType.MISSED_WHILE_AWAY,
}


class EventStore(TypingProtocol):
    def add_event(self, ev: ConnectionEvent) -> bool: ...
    def apply_upgrade(self, up: Upgrade) -> None: ...


class ConnectionDetector:
    def __init__(
        self,
        wts: Optional[WtsMonitor] = None,
        eventlog: Optional[EventLogMonitor] = None,
        network: Optional[NetworkMonitor] = None,
        tools: Optional[RemoteToolsDetector] = None,
        storage: Optional[EventStore] = None,
        rdp_config_func=read_rdp_config,
        eventlog_interval: float = 5.0,
        tools_interval: float = 6.0,
        rdpcfg_interval: float = 300.0,
        clock=None,
    ) -> None:
        self.wts = wts or WtsMonitor()
        self.eventlog = eventlog if eventlog is not None else EventLogMonitor()
        self.network = network or NetworkMonitor()
        self.tools = tools or RemoteToolsDetector()
        self.storage = storage
        self.sessions = SessionManager()
        self.correlator = Correlator()
        self._rdp_config_func = rdp_config_func
        self.eventlog_interval = eventlog_interval
        self.tools_interval = tools_interval
        self.rdpcfg_interval = rdpcfg_interval
        self._clock = clock or (lambda: datetime.now().astimezone())

        self._last_eventlog: Optional[datetime] = None
        self._last_tools: Optional[datetime] = None
        self._last_rdpcfg: Optional[datetime] = None
        self.rdp_config = RdpServerConfig()
        self._tools_cache: list[RemoteToolStatus] = []
        self._network_cache: list[NetworkConnection] = []
        self._own_state: Optional[SessionState] = None
        self._away_events: list[ConnectionEvent] = []
        self._away_since: Optional[datetime] = None
        self._remote_controlled = False
        self.last_snapshot: Optional[WtsSnapshot] = None
        self.last_result: Optional[CycleResult] = None

    # ------------------------------------------------------------------ helpers
    def _due(self, last: Optional[datetime], interval: float, now: datetime, force: bool) -> bool:
        return force or last is None or (now - last).total_seconds() >= interval

    def sources(self) -> dict[str, SourceStatus]:
        out: dict[str, SourceStatus] = {}
        if self.last_snapshot:
            out["wts"] = self.last_snapshot.status
        out.update(self.eventlog.statuses())
        out["tcp"] = self.network.status
        out["procs"] = self.tools.status
        return out

    # ------------------------------------------------------------------ main
    def run_cycle(self, force: bool = False) -> CycleResult:
        t0 = time.perf_counter()
        now = self._clock()
        errors: list[str] = []
        new_events: list[ConnectionEvent] = []

        # 1. Настройки RDP (редко)
        if self._due(self._last_rdpcfg, self.rdpcfg_interval, now, force):
            self._last_rdpcfg = now
            try:
                self.rdp_config = self._rdp_config_func()
            except Exception as e:  # noqa: BLE001
                errors.append(f"Чтение настроек RDP: {e}")

        # 2. Сеансы WTS
        try:
            snap = self.wts.snapshot()
        except Exception as e:  # noqa: BLE001
            log.exception("WTS snapshot failed")
            snap = WtsSnapshot([], SourceStatus("wts", "WTS API", SourceState.ERROR, f"Ошибка: {e}"))
        self.last_snapshot = snap
        errors.extend(snap.errors)
        if snap.status.usable:
            try:
                new_events.extend(self.sessions.update(snap.sessions, now))
            except Exception as e:  # noqa: BLE001
                log.exception("Session diff failed")
                errors.append(f"Сравнение сеансов: {e}")

        # 3. Теневое подключение к текущему сеансу (SM_REMOTECONTROL)
        if snap.current_is_remote_controlled != self._remote_controlled:
            etype = EventType.SHADOW_START if snap.current_is_remote_controlled else EventType.SHADOW_STOP
            new_events.append(ConnectionEvent(
                timestamp=now, event_type=etype, source="GetSystemMetrics(SM_REMOTECONTROL)",
                confidence=Confidence.HIGH, session_id=snap.current_session_id,
                details="Windows сообщает, что текущий сеанс управляется удалённо (теневое подключение)."
                if snap.current_is_remote_controlled else "Удалённое управление текущим сеансом прекратилось.",
                key=f"smrc:{etype.value}:{now.timestamp():.0f}",
            ))
            self._remote_controlled = snap.current_is_remote_controlled

        # 4. TCP-соединения с RDP-портом
        try:
            self._network_cache, net_events = self.network.poll(self.rdp_config.port, now)
            new_events.extend(net_events)
        except Exception as e:  # noqa: BLE001
            errors.append(f"TCP: {e}")

        # 5. Журналы событий
        if self.eventlog is not None and self._due(self._last_eventlog, self.eventlog_interval, now, force):
            self._last_eventlog = now
            try:
                new_events.extend(self.eventlog.poll(now))
            except Exception as e:  # noqa: BLE001
                log.exception("Event log poll failed")
                errors.append(f"Журналы: {e}")

        # 6. Средства удалённого доступа
        if self._due(self._last_tools, self.tools_interval, now, force):
            self._last_tools = now
            try:
                self._tools_cache, tool_events = self.tools.scan(now, snap.current_session_id)
                new_events.extend(tool_events)
            except Exception as e:  # noqa: BLE001
                log.exception("Remote tools scan failed")
                errors.append(f"Процессы: {e}")

        # 7. Корреляция
        upgrades: list[Upgrade] = []
        try:
            upgrades = self.correlator.process(new_events)
        except Exception as e:  # noqa: BLE001
            log.exception("Correlation failed")
            errors.append(f"Корреляция: {e}")

        # 8. «Пока вас не было»
        new_events.extend(self._track_own_session(snap, new_events, now))

        # 9. Сохранение
        notify: list[ConnectionEvent] = []
        for ev in new_events:
            is_new = True
            if self.storage is not None:
                try:
                    is_new = self.storage.add_event(ev)
                except Exception as e:  # noqa: BLE001
                    errors.append(f"База данных: {e}")
            if ev.event_type == EventType.RDP_ACTIVE_AT_START:
                is_new = True  # о текущем подключении сообщаем при каждом запуске
            if is_new and not ev.historical and ev.event_type in NOTIFY_TYPES and self._worth_notifying(ev):
                notify.append(ev)
        if self.storage is not None:
            for up in upgrades:
                try:
                    self.storage.apply_upgrade(up)
                except Exception as e:  # noqa: BLE001
                    errors.append(f"База данных: {e}")

        overall, title, reasons = self.evaluate(snap)
        sources = self.sources()
        result = CycleResult(
            timestamp=now, sessions=snap.sessions, network=self._network_cache, remote_tools=self._tools_cache,
            sources=sources, new_events=new_events, notify_events=notify, overall=overall, overall_title=title,
            overall_reasons=reasons, current_session_id=snap.current_session_id,
            current_session_remote=snap.current_is_remote, rdp_server_enabled=self.rdp_config.enabled,
            rdp_port=self.rdp_config.port, cycle_ms=(time.perf_counter() - t0) * 1000, errors=errors,
        )
        self.last_result = result
        return result

    @staticmethod
    def _worth_notifying(ev: ConnectionEvent) -> bool:
        if ev.event_type == EventType.RDP_STATE_CHANGE:
            return ev.confidence >= Confidence.HIGH
        if ev.event_type == EventType.REMOTE_TOOL_STARTED:
            return True
        return ev.confidence >= Confidence.LOW

    def _track_own_session(self, snap: WtsSnapshot, events: list[ConnectionEvent], now: datetime) -> list[ConnectionEvent]:
        own = next((s for s in snap.sessions if s.is_current), None)
        state = own.state if own else None
        out: list[ConnectionEvent] = []
        if state is not None and state != SessionState.ACTIVE:
            if self._away_since is None:
                self._away_since = now
            self._away_events.extend(
                e for e in events if e.event_type in (CONNECT_TYPES | DISCONNECT_TYPES | {EventType.RDP_AUTH})
                and e.confidence >= Confidence.MEDIUM
            )
        elif state == SessionState.ACTIVE and self._away_since is not None:
            if self._away_events:
                lines = [f"{e.timestamp:%H:%M:%S} {e.type_label}: {e.user or '—'} {e.ip or ''}".strip()
                         for e in self._away_events[-10:]]
                out.append(ConnectionEvent(
                    timestamp=now, event_type=EventType.MISSED_WHILE_AWAY, source="Монитор",
                    confidence=max(e.confidence for e in self._away_events),
                    details=(f"Пока ваш сеанс был отключён (с {self._away_since:%d.%m %H:%M:%S}), "
                             f"зарегистрировано событий: {len(self._away_events)}. " + "; ".join(lines)),
                    key=f"away:{now.timestamp():.0f}",
                ))
            self._away_since = None
            self._away_events = []
        self._own_state = state
        return out

    def evaluate(self, snap: WtsSnapshot) -> tuple[OverallStatus, str, list[str]]:
        reasons: list[str] = []
        remote = [s for s in snap.sessions if s.is_remote_live]
        if remote:
            for s in remote:
                reasons.append(f"Сеанс {s.session_id}: {s.full_user or 'вход не выполнен'}"
                               f" с {s.client_ip or s.client_name or 'неизвестного адреса'}")
            return OverallStatus.CONNECTED, "Обнаружено активное RDP-подключение", reasons
        if snap.current_is_remote:
            return OverallStatus.CONNECTED, "Обнаружено активное RDP-подключение", [
                "Windows сообщает, что текущий сеанс является удалённым (SM_REMOTESESSION)."]
        if snap.current_is_remote_controlled:
            return OverallStatus.CONNECTED, "Ваш сеанс управляется удалённо (теневое подключение)", [
                "Windows сообщает, что текущий сеанс удалённо управляется (SM_REMOTECONTROL)."]

        if not snap.status.usable:
            reasons.append(snap.status.message or "Сведения о сеансах недоступны.")
            reasons.append("Отсутствие обнаруженных подключений не означает, что их нет.")
            return OverallStatus.INSUFFICIENT, "Недостаточно данных для определения состояния", reasons

        suspicious = []
        for t in self._tools_cache:
            if t.suspicious and t.running:
                suspicious.append(f"{t.name}: {', '.join(t.processes)}")
        if self._network_cache:
            for c in self._network_cache:
                suspicious.append(f"Открыто TCP-соединение с RDP-портом от {c.remote_ip}, но RDP-сеанс не обнаружен "
                                  f"(возможна попытка входа или экран входа).")
        if suspicious:
            return OverallStatus.INSUFFICIENT, "Обнаружены признаки удалённой активности — требуется проверка", suspicious

        if snap.status.state == SourceState.PARTIAL:
            reasons.append("Часть сведений о сеансах недоступна: " + snap.status.message)
        if snap.used_fallback:
            reasons.append("Используется резервный источник «query user».")
        if self.rdp_config.enabled is False:
            reasons.append("Входящие RDP-подключения отключены в настройках Windows.")
        elif self.rdp_config.enabled:
            reasons.append(f"RDP-сервер включён (порт {self.rdp_config.port}) — входящие подключения возможны.")
        running = [t.name for t in self._tools_cache if t.running and not t.suspicious]
        if running:
            reasons.append("Запущены средства удалённого доступа: " + ", ".join(running) + " (статус подключения неизвестен).")
        reasons.append("Отсутствие RDP-сеанса не исключает других средств удалённого доступа.")
        return OverallStatus.NO_CONNECTIONS, "Удалённых подключений не обнаружено", reasons


def today_start(now: Optional[datetime] = None) -> datetime:
    now = now or datetime.now().astimezone()
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


def days_ago(days: int, now: Optional[datetime] = None) -> datetime:
    return (now or datetime.now().astimezone()) - timedelta(days=days)
