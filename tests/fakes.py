"""Подставные источники данных для тестов (без Windows)."""
from __future__ import annotations

from datetime import datetime, timedelta

from core.eventlog_monitor import EventLogAccessError, EventLogMonitor, RawEvent
from core.models import Protocol, SessionInfo, SessionState, SourceState, SourceStatus
from core.network_monitor import NetworkMonitor, RdpServerConfig
from core.remote_tools_detector import RemoteToolsDetector
from core.wts_monitor import WtsSnapshot

T0 = datetime(2026, 10, 28, 14, 32, 10).astimezone()


def console(sid=1, user="aziz", state=SessionState.ACTIVE, current=True):
    return SessionInfo(session_id=sid, winstation="Console", state=state, user=user, domain="ALIF",
                       protocol=Protocol.CONSOLE, is_current=current, logon_time=T0 - timedelta(hours=3))


def rdp(sid=2, user="user01", ip="192.168.1.50", state=SessionState.ACTIVE, logon=None):
    return SessionInfo(session_id=sid, winstation=f"RDP-Tcp#{sid}" if state != SessionState.DISCONNECTED else "",
                       state=state, user=user, domain="ALIF", client_ip=ip, client_name="ADMIN-PC",
                       protocol=Protocol.RDP, logon_time=logon or T0 - timedelta(minutes=1))


class FakeWts:
    def __init__(self, sessions=None, status=SourceState.AVAILABLE, remote_controlled=False, current_remote=False):
        self.sessions = list(sessions or [console()])
        self.state = status
        self.remote_controlled = remote_controlled
        self.current_remote = current_remote

    def snapshot(self):
        st = SourceStatus("wts", "WTS API", self.state, "fake")
        return WtsSnapshot([s for s in self.sessions], st, current_session_id=1, console_session_id=1,
                           current_is_remote=self.current_remote, current_is_remote_controlled=self.remote_controlled)


class FakeLogs:
    """query_func для EventLogMonitor: channel -> list[RawEvent] или исключение."""

    def __init__(self, data=None, denied=()):
        self.data = data or {}
        self.denied = set(denied)
        self.calls = []

    def __call__(self, channel, xpath, reverse, limit):
        self.calls.append((channel, xpath))
        if channel in self.denied:
            raise EventLogAccessError(channel, 5, "Access is denied")
        evs = list(self.data.get(channel, []))
        if "EventRecordID >" in xpath:
            n = int(xpath.split("EventRecordID >")[1].split()[0].rstrip("]"))
            evs = [e for e in evs if e.record_id > n]
        if xpath == "*":
            evs = sorted(evs, key=lambda e: -e.record_id)[:1]
        return evs[::-1] if reverse else evs


def raw(channel, eid, rec, ts, **data):
    return RawEvent(channel, eid, rec, ts, "", {k: str(v) for k, v in data.items()})


def make_detector(wts=None, logs=None, procs=None, storage=None, include_security=True):
    from core.connection_detector import ConnectionDetector
    elog = EventLogMonitor(lookback_days=7, query_func=logs or FakeLogs(), include_security=include_security)
    elog.started_at = T0 - timedelta(minutes=10)
    return ConnectionDetector(
        wts=wts or FakeWts(), eventlog=elog,
        network=NetworkMonitor(connections_func=lambda: []),
        tools=RemoteToolsDetector(process_func=procs or (lambda: []), exists_func=lambda p: False,
                                  session_func=lambda pid: 1),
        storage=storage, rdp_config_func=lambda: RdpServerConfig(enabled=True, port=3389),
        eventlog_interval=0, tools_interval=0,
    )
