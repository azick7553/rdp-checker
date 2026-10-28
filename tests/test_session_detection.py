"""Сценарии 2–4: определение RDP-сеансов и изменений их состояния."""
from datetime import timedelta

from core.models import Confidence, EventType, OverallStatus, Protocol, SessionInfo, SessionState, SourceState
from core.session_manager import SessionManager
from core.winapi import filetime_to_datetime, parse_client_address
from core.wts_monitor import parse_quser
from tests.fakes import T0, FakeWts, console, make_detector, rdp


def types(events):
    return [e.event_type for e in events]


# ---------------------------------------------------------------- SessionManager
def test_no_rdp_sessions_no_events():
    m = SessionManager()
    assert m.update([console()], T0) == []
    assert m.update([console()], T0 + timedelta(seconds=2)) == []


def test_new_rdp_session_detected_once():
    m = SessionManager()
    m.update([console()], T0)
    ev = m.update([console(), rdp()], T0 + timedelta(seconds=2))
    assert types(ev) == [EventType.RDP_CONNECT]
    assert ev[0].confidence == Confidence.CONFIRMED
    assert ev[0].ip == "192.168.1.50"
    assert ev[0].session_id == 2
    # повторный опрос без изменений — никаких повторных событий
    assert m.update([console(), rdp()], T0 + timedelta(seconds=4)) == []


def test_rdp_session_present_at_start():
    m = SessionManager()
    ev = m.update([console(), rdp()], T0)
    assert types(ev) == [EventType.RDP_ACTIVE_AT_START]
    # ключ стабилен между перезапусками (дедупликация в БД)
    ev2 = SessionManager().update([console(), rdp()], T0 + timedelta(minutes=5))
    assert ev[0].key == ev2[0].key


def test_disconnect_reconnect_logoff():
    m = SessionManager()
    m.update([console(), rdp()], T0)
    ev = m.update([console(), rdp(state=SessionState.DISCONNECTED)], T0 + timedelta(seconds=2))
    assert types(ev) == [EventType.RDP_DISCONNECT]
    ev = m.update([console(), rdp()], T0 + timedelta(seconds=4))
    assert types(ev) == [EventType.RDP_RECONNECT]
    ev = m.update([console()], T0 + timedelta(seconds=6))
    assert types(ev) == [EventType.RDP_LOGOFF]


def test_console_session_taken_over_remotely():
    m = SessionManager()
    m.update([console()], T0)
    taken = console()
    taken.protocol = Protocol.RDP
    taken.winstation = "RDP-Tcp#5"
    taken.client_ip = "10.0.0.7"
    ev = m.update([taken], T0 + timedelta(seconds=2))
    assert types(ev) == [EventType.RDP_CONNECT]
    assert "консол" in ev[0].details.lower() or "локальный" in ev[0].details.lower()


def test_new_client_ip_on_live_session_is_reconnect():
    m = SessionManager()
    m.update([rdp(ip="10.0.0.1")], T0)
    ev = m.update([rdp(ip="10.0.0.2")], T0 + timedelta(seconds=2))
    assert types(ev) == [EventType.RDP_RECONNECT]


def test_login_screen_without_user_is_high_not_confirmed():
    m = SessionManager()
    m.update([console()], T0)
    s = rdp(user="")
    ev = m.update([console(), s], T0 + timedelta(seconds=2))
    assert ev[0].event_type == EventType.RDP_CONNECT
    assert ev[0].confidence == Confidence.HIGH


def test_listener_and_services_ignored():
    m = SessionManager()
    listener = SessionInfo(session_id=65536, winstation="RDP-Tcp", state=SessionState.LISTEN)
    services = SessionInfo(session_id=0, winstation="Services", state=SessionState.DISCONNECTED)
    assert m.update([services, listener, console()], T0) == []
    assert not listener.is_remote and not services.is_remote


def test_session_id_reuse_detected():
    m = SessionManager()
    m.update([rdp(sid=3, logon=T0 - timedelta(hours=1))], T0)
    ev = m.update([rdp(sid=3, user="other", logon=T0)], T0 + timedelta(seconds=2))
    assert types(ev) == [EventType.RDP_LOGOFF, EventType.RDP_CONNECT]


# ---------------------------------------------------------------- overall status
def test_overall_green_when_sources_available_and_no_rdp():
    d = make_detector(wts=FakeWts([console()]))
    r = d.run_cycle()
    assert r.overall == OverallStatus.NO_CONNECTIONS


def test_overall_red_with_active_rdp_and_notification():
    wts = FakeWts([console()])
    d = make_detector(wts=wts)
    d.run_cycle()
    wts.sessions.append(rdp())
    r = d.run_cycle()
    assert r.overall == OverallStatus.CONNECTED
    assert [e.event_type for e in r.notify_events] == [EventType.RDP_CONNECT]


def test_overall_yellow_when_wts_denied():
    d = make_detector(wts=FakeWts([], status=SourceState.DENIED))
    r = d.run_cycle()
    assert r.overall == OverallStatus.INSUFFICIENT
    assert "Недостаточно данных" in r.overall_title


def test_remote_controlled_session_is_red():
    d = make_detector(wts=FakeWts([console()], remote_controlled=True))
    r = d.run_cycle()
    assert r.overall == OverallStatus.CONNECTED
    assert any(e.event_type == EventType.SHADOW_START for e in r.new_events)


def test_disconnect_scenario_updates_state_and_stores(tmp_path):
    from services.storage import Storage
    st = Storage(tmp_path / "h.db")
    wts = FakeWts([console(), rdp()])
    d = make_detector(wts=wts, storage=st)
    d.run_cycle()
    wts.sessions[1] = rdp(state=SessionState.DISCONNECTED)
    r = d.run_cycle()
    assert r.overall == OverallStatus.NO_CONNECTIONS
    rows = st.query()
    assert any(row.event_type == EventType.RDP_DISCONNECT.value for row in rows)


def test_missed_while_away_summary():
    wts = FakeWts([console()])
    d = make_detector(wts=wts)
    d.run_cycle()
    wts.sessions = [console(state=SessionState.DISCONNECTED), rdp(sid=3, user="admin")]
    d.run_cycle()
    wts.sessions = [console()]
    r = d.run_cycle()
    assert any(e.event_type == EventType.MISSED_WHILE_AWAY for e in r.notify_events)


# ---------------------------------------------------------------- parsing helpers
def test_parse_client_address_ipv4_offset():
    raw = bytes([0, 0, 192, 168, 1, 50] + [0] * 14)
    assert parse_client_address(2, raw) == "192.168.1.50"
    assert parse_client_address(0, raw) == ""
    assert parse_client_address(2, bytes(20)) == ""


def test_parse_client_address_ipv6():
    raw = bytes([0xFE, 0x80] + [0] * 13 + [1] + [0] * 4)
    assert parse_client_address(23, raw) == "fe80::1"


def test_filetime_conversion():
    assert filetime_to_datetime(0) is None
    dt = filetime_to_datetime(133_000_000_000_000_000)
    assert dt is not None and dt.year == 2022


def test_parse_quser_english():
    out = (" USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME\n"
           ">aziz                  console             1  Active      none   10/28/2026 9:01 AM\n"
           " user01                rdp-tcp#3           2  Active          .  10/28/2026 2:32 PM\n"
           " olduser                                   4  Disc        1:02  10/27/2026 6:00 PM\n")
    s = parse_quser(out)
    assert [x.session_id for x in s] == [1, 2, 4]
    assert s[0].is_current and s[0].protocol == Protocol.CONSOLE
    assert s[1].is_remote and s[1].state == SessionState.ACTIVE
    assert s[2].state == SessionState.DISCONNECTED


def test_parse_quser_russian():
    out = (" ПОЛЬЗОВАТЕЛЬ          СЕАНС              ID  СТАТУС  БЕЗДЕЙСТВ. ВРЕМЯ ВХОДА\n"
           ">aziz                  console             1  Активно      нет   28.10.2026 9:01\n"
           " user01                rdp-tcp#3           2  Активно        .   28.10.2026 14:32\n")
    s = parse_quser(out)
    assert len(s) == 2
    assert s[1].is_remote_live
    assert s[1].logon_time is not None and s[1].logon_time.hour == 14
