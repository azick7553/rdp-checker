"""Уведомления (дедупликация, категории, текст) и сценарий 8 (AnyDesk)."""
from datetime import timedelta

from app.config import Settings
from core.models import Confidence, ConnectionEvent, EventType, ToolConnectionStatus
from core.remote_tools_detector import RemoteToolsDetector, parse_anydesk_trace, parse_teamviewer_incoming
from services.notifications import NotificationService, format_notification
from tests.fakes import T0, FakeWts, console, make_detector, rdp


def ev(etype=EventType.RDP_CONNECT, conf=Confidence.CONFIRMED, key="k1", ip="192.168.1.50", user="ALIF\\user01",
       sid=2, ts=T0, source="WTS API"):
    return ConnectionEvent(ts, etype, source, conf, user=user, ip=ip, session_id=sid, key=key)


def service(settings=None):
    shown = []
    s = NotificationService(settings or Settings().validate(), shown.append, clock=lambda: T0)
    return s, shown


def test_notification_text_matches_spec():
    n = format_notification(ev())
    assert n.title == "Внимание! RDP-подключение"
    assert "Обнаружена новая удалённая сессия." in n.body
    assert "Пользователь: ALIF\\user01" in n.body
    assert "IP: 192.168.1.50" in n.body
    assert "Время: " in n.body


def test_unknown_ip_shown_as_unavailable():
    n = format_notification(ev(ip=""))
    assert "IP: Недоступен" in n.body


def test_same_event_not_notified_twice():
    s, shown = service()
    s.handle([ev()])
    s.handle([ev()])
    assert len(shown) == 1


def test_same_incident_from_multiple_sources_merged():
    s, shown = service()
    s.handle([ev(key="wts"), ev(key="evt:LSM:1", conf=Confidence.HIGH, source="Журнал LSM (ID 21)"),
              ev(EventType.RDP_SHELL_START, Confidence.HIGH, key="evt:LSM:2")])
    s.handle([ev(EventType.RDP_AUTH, Confidence.HIGH, key="evt:RCM:3", sid=None)])
    assert len(shown) == 1
    assert shown[0].event.key == "wts"


def test_low_auth_then_confirmed_connect_both_notified():
    s, shown = service()
    s.handle([ev(EventType.RDP_AUTH, Confidence.LOW, key="a", sid=None)])
    s.handle([ev(key="b")])
    assert [n.event.key for n in shown] == ["a", "b"]
    assert "не подтвержд" in shown[0].body


def test_different_clients_are_separate_incidents():
    s, shown = service()
    s.handle([ev(key="a", ip="10.0.0.1"), ev(key="b", ip="10.0.0.2", sid=3)])
    assert len(shown) == 2


def test_category_can_be_disabled():
    st = Settings().validate()
    st.notify["disconnect"] = False
    s, shown = service(st)
    s.handle([ev(EventType.RDP_DISCONNECT, key="d")])
    assert shown == []
    s.handle([ev(EventType.RDP_RECONNECT, key="r")])
    assert len(shown) == 1


def test_global_disable():
    st = Settings().validate()
    st.notifications_enabled = False
    s, shown = service(st)
    s.handle([ev()])
    assert shown == []


def test_detector_does_not_repeat_notifications_each_cycle():
    wts = FakeWts([console()])
    d = make_detector(wts=wts)
    d.run_cycle()
    wts.sessions.append(rdp())
    total = []
    for _ in range(5):
        total += d.run_cycle().notify_events
    assert len(total) == 1


def test_settings_interval_clamped():
    s = Settings(poll_interval=100).validate()
    assert s.poll_interval == 30
    assert Settings(poll_interval=0).validate().poll_interval == 1


def test_settings_roundtrip():
    s = Settings(poll_interval=5)
    s.notify["auth"] = False
    s.save()
    loaded = Settings.load()
    assert loaded.poll_interval == 5 and loaded.notify["auth"] is False


# ---------------------------------------------------------------- Scenario 8
def test_anydesk_process_detected_but_connection_not_claimed():
    det = RemoteToolsDetector(process_func=lambda: [(4321, "AnyDesk.exe", "ALIF\\aziz")],
                              exists_func=lambda p: False, session_func=lambda pid: 1)
    statuses, events = det.scan(T0, current_session=1)
    ad = next(s for s in statuses if s.key == "anydesk")
    assert ad.running and ad.installed
    assert ad.connection == ToolConnectionStatus.UNKNOWN
    assert ad.connection != ToolConnectionStatus.CONFIRMED
    assert not ad.suspicious
    assert any("ваш сеанс" in p for p in ad.processes)
    started = [e for e in events if e.event_type == EventType.REMOTE_TOOL_STARTED]
    assert started and started[0].confidence == Confidence.INFO
    assert "не означает" in started[0].details


def test_anydesk_does_not_make_status_red():
    d = make_detector(procs=lambda: [(4321, "AnyDesk.exe", None)])
    r = d.run_cycle()
    assert r.overall.value == "green"
    assert any("AnyDesk" in reason for reason in r.overall_reasons)


def test_shadow_components_are_suspicious_but_not_red():
    d = make_detector(procs=lambda: [(99, "RdpSaProxy.exe", None)])
    r = d.run_cycle()
    assert r.overall.value == "yellow"
    assert any(e.event_type == EventType.SHADOW_SUSPECTED and e.confidence == Confidence.MEDIUM
               for e in r.notify_events)


def test_teamviewer_log_parsing():
    text = ("123456789\tJohn Admin\t28-10-2026 14:32:10\t28-10-2026 14:40:00\taziz\tRemoteControl\t{guid}\n"
            "garbage line\n")
    recs = parse_teamviewer_incoming(text)
    assert len(recs) == 1 and recs[0].start.hour == 14 and recs[0].end.minute == 40


def test_anydesk_trace_parsing():
    text = ("Incoming    2026-10-28, 14:32    User    123456789    123456789\n"
            "Outgoing    2026-10-28, 15:00    User    987654321    987654321\n")
    recs = parse_anydesk_trace(text)
    assert len(recs) == 1 and recs[0].partner == "ID 123456789"


def test_tool_log_new_entry_notifies_once(monkeypatch):
    monkeypatch.setenv("APPDATA", "C:/Users/aziz/AppData/Roaming")
    content = {"text": "Incoming    2026-10-27, 10:00    User    111    111\n"}
    mtime = {"v": 1.0}
    det = RemoteToolsDetector(process_func=lambda: [], exists_func=lambda p: p.endswith("connection_trace.txt"),
                              read_func=lambda p: content["text"], mtime_func=lambda p: mtime["v"],
                              session_func=lambda pid: None)
    _, ev1 = det.scan(T0)
    assert all(e.historical for e in ev1 if e.event_type == EventType.REMOTE_TOOL_INCOMING)
    content["text"] += "Incoming    2026-10-28, 14:00    User    222    222\n"
    mtime["v"] = 2.0
    _, ev2 = det.scan(T0 + timedelta(minutes=1))
    inc = [e for e in ev2 if e.event_type == EventType.REMOTE_TOOL_INCOMING]
    assert len(inc) == 1 and not inc[0].historical and "222" in inc[0].details
