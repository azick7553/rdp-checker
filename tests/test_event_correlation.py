"""Разбор журналов Windows, корреляция и сценарий 5 (Security недоступен)."""
from datetime import timedelta

from core.correlation import Correlator
from core.eventlog_monitor import (
    LSM_CHANNEL, RCM_CHANNEL, SECURITY_CHANNEL, EventLogMonitor, build_xpath, ChannelQuery, map_event,
    parse_event_xml,
)
from core.models import Confidence, ConnectionEvent, EventType, OverallStatus, SourceState
from tests.fakes import T0, FakeLogs, FakeWts, console, make_detector, raw, rdp

LSM21_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-TerminalServices-LocalSessionManager"/><EventID>21</EventID>
<TimeCreated SystemTime="2026-10-28T09:32:10.1234567Z"/><EventRecordID>1042</EventRecordID>
<Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel></System>
<UserData><EventXML xmlns="Event_NS"><User>ALIF\\user01</User><SessionID>2</SessionID>
<Address>192.168.1.50</Address></EventXML></UserData></Event>"""

RCM1149_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><EventID>1149</EventID><TimeCreated SystemTime="2026-10-28T09:32:05.000Z"/>
<EventRecordID>77</EventRecordID><Channel>Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational</Channel></System>
<UserData><EventXML xmlns="Event_NS"><Param1>user01</Param1><Param2>ALIF</Param2><Param3>192.168.1.50</Param3></EventXML></UserData></Event>"""

SEC4624_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><EventID>4624</EventID><TimeCreated SystemTime="2026-10-28T09:32:08Z"/><EventRecordID>555</EventRecordID>
<Channel>Security</Channel></System><EventData><Data Name="TargetUserName">user01</Data>
<Data Name="TargetDomainName">ALIF</Data><Data Name="LogonType">10</Data><Data Name="IpAddress">192.168.1.50</Data>
<Data Name="WorkstationName">ADMIN-PC</Data></EventData></Event>"""


def test_parse_lsm21_xml():
    r = parse_event_xml(LSM21_XML)
    assert r.event_id == 21 and r.record_id == 1042
    assert r.data["Address"] == "192.168.1.50" and r.data["SessionID"] == "2"
    ev = map_event(r)
    assert ev.event_type == EventType.RDP_CONNECT
    assert ev.confidence == Confidence.HIGH
    assert ev.ip == "192.168.1.50" and ev.session_id == 2
    assert ev.key == "evt:LSM:1042"


def test_lsm21_local_is_not_remote():
    r = raw(LSM_CHANNEL, 21, 1, T0, User="ALIF\\aziz", SessionID=1, Address="LOCAL")
    assert map_event(r).event_type == EventType.LOCAL_LOGON
    assert map_event(raw(LSM_CHANNEL, 25, 2, T0, User="x", SessionID=1, Address="LOCAL")) is None


def test_1149_alone_is_low_confidence():
    ev = map_event(parse_event_xml(RCM1149_XML))
    assert ev.event_type == EventType.RDP_AUTH
    assert ev.confidence == Confidence.LOW
    assert ev.user == "ALIF\\user01" and ev.ip == "192.168.1.50"
    c = Correlator()
    c.process([ev])
    assert ev.confidence == Confidence.LOW


def test_1149_upgraded_by_session_logon_later():
    auth = map_event(parse_event_xml(RCM1149_XML))
    logon = map_event(parse_event_xml(LSM21_XML))
    c = Correlator()
    c.process([auth])
    ups = c.process([logon])
    assert auth.confidence == Confidence.HIGH
    assert any(u.key == auth.key for u in ups)


def test_two_sources_give_confirmed():
    lsm = map_event(parse_event_xml(LSM21_XML))
    sec = map_event(parse_event_xml(SEC4624_XML))
    assert sec.event_type == EventType.RDP_CONNECT
    c = Correlator()
    c.process([lsm, sec])
    assert lsm.confidence == Confidence.CONFIRMED and sec.confidence == Confidence.CONFIRMED


def test_unrelated_events_not_correlated():
    auth = map_event(parse_event_xml(RCM1149_XML))
    other = ConnectionEvent(T0 + timedelta(hours=2), EventType.RDP_CONNECT, "Журнал LSM (ID 21)",
                            Confidence.HIGH, user="ALIF\\user01", ip="192.168.1.50", key="x")
    c = Correlator()
    c.process([auth, other])
    assert auth.confidence == Confidence.LOW


def test_logoff_reclassified_for_remote_session():
    c = Correlator()
    logon = map_event(raw(LSM_CHANNEL, 21, 1, T0, User="ALIF\\user01", SessionID=2, Address="10.1.1.1"))
    logoff = map_event(raw(LSM_CHANNEL, 23, 2, T0 + timedelta(minutes=30), User="ALIF\\user01", SessionID=2))
    c.process([logon, logoff])
    assert logoff.event_type == EventType.RDP_LOGOFF
    assert logoff.ip == "10.1.1.1"


def test_security_type2_ignored_and_4778_console_ignored():
    assert map_event(raw(SECURITY_CHANNEL, 4624, 1, T0, TargetUserName="a", LogonType=2)) is None
    assert map_event(raw(SECURITY_CHANNEL, 4778, 2, T0, AccountName="a", ClientAddress="LOCAL",
                         SessionName="Console")) is None
    ev = map_event(raw(SECURITY_CHANNEL, 4778, 3, T0, AccountName="a", AccountDomain="D",
                       ClientAddress="10.0.0.5", SessionName="RDP-Tcp#4", ClientName="PC"))
    assert ev.event_type == EventType.RDP_RECONNECT and ev.ip == "10.0.0.5"


def test_shadow_events_mapped():
    ev = map_event(raw(RCM_CHANNEL, 20506, 9, T0, Param1="ADMIN\\it", Param2="1"))
    assert ev.event_type == EventType.SHADOW_START and ev.confidence == Confidence.HIGH


def test_xpath_building():
    q = ChannelQuery(SECURITY_CHANNEL, "(EventID=4624)", " and EventData[Data[@Name='LogonType']='10']")
    xp = build_xpath(q, 100, None)
    assert xp == "*[System[(EventID=4624) and EventRecordID > 100] and EventData[Data[@Name='LogonType']='10']]"
    assert "timediff" in build_xpath(q, None, 1000)


def test_eventlog_incremental_reading_without_duplicates():
    logs = FakeLogs({LSM_CHANNEL: [raw(LSM_CHANNEL, 21, 10, T0, User="u", SessionID=2, Address="1.2.3.4")]})
    m = EventLogMonitor(query_func=logs, include_security=False)
    first = m.poll(T0)
    assert len(first) == 1
    assert m.poll(T0) == []
    logs.data[LSM_CHANNEL].append(raw(LSM_CHANNEL, 24, 11, T0, User="u", SessionID=2, Address="1.2.3.4"))
    nxt = m.poll(T0)
    assert [e.event_type for e in nxt] == [EventType.RDP_DISCONNECT]


def test_eventlog_empty_window_does_not_reread_old_records():
    old = raw(LSM_CHANNEL, 21, 5, T0 - timedelta(days=60), User="u", SessionID=2, Address="1.2.3.4")

    class Logs(FakeLogs):
        def __call__(self, channel, xpath, reverse, limit):
            if "timediff" in xpath:
                return []
            return super().__call__(channel, xpath, reverse, limit)

    m = EventLogMonitor(query_func=Logs({LSM_CHANNEL: [old]}), include_security=False)
    m.poll(T0)
    assert m.poll(T0) == []


# ---------------------------------------------------------------- Scenario 5
def test_security_log_denied_monitor_continues():
    logs = FakeLogs({LSM_CHANNEL: []}, denied={SECURITY_CHANNEL})
    wts = FakeWts([console()])
    d = make_detector(wts=wts, logs=logs)
    r = d.run_cycle()
    sec = r.sources["evt:Security"]
    assert sec.state == SourceState.DENIED
    assert "Security Event Log" in sec.message
    assert r.sources["evt:LSM"].state == SourceState.AVAILABLE
    assert r.overall == OverallStatus.NO_CONNECTIONS
    wts.sessions.append(rdp())
    r = d.run_cycle()
    assert r.overall == OverallStatus.CONNECTED


def test_all_logs_denied_and_crashing_source_do_not_crash():
    logs = FakeLogs(denied={LSM_CHANNEL, RCM_CHANNEL, SECURITY_CHANNEL})
    d = make_detector(logs=logs)

    def boom():
        raise RuntimeError("tcp boom")

    d.network._get = boom
    r = d.run_cycle()
    assert r.overall in (OverallStatus.NO_CONNECTIONS, OverallStatus.INSUFFICIENT)
    assert r.sources["tcp"].state == SourceState.ERROR


def test_historical_events_not_notified():
    old = raw(LSM_CHANNEL, 21, 1, T0 - timedelta(days=2), User="ALIF\\x", SessionID=3, Address="10.9.9.9")
    d = make_detector(logs=FakeLogs({LSM_CHANNEL: [old]}))
    r = d.run_cycle()
    assert any(e.event_type == EventType.RDP_CONNECT for e in r.new_events)
    assert r.notify_events == []


def test_cleared_log_resets_cursor():
    from core.eventlog_monitor import LSM_CHANNEL
    logs = FakeLogs({LSM_CHANNEL: [raw(LSM_CHANNEL, 21, 500, T0, User="u", SessionID=2, Address="1.2.3.4")]})
    m = EventLogMonitor(query_func=logs, include_security=False)
    m.queries = [q for q in m.queries if q.channel == LSM_CHANNEL]
    m.poll(T0)
    logs.data[LSM_CHANNEL] = []          # журнал очищен
    for _ in range(20):
        m.poll(T0)
    logs.data[LSM_CHANNEL] = [raw(LSM_CHANNEL, 25, 3, T0, User="u", SessionID=2, Address="1.2.3.4")]
    for _ in range(20):
        evs = m.poll(T0)
        if evs:
            break
    assert [e.event_type for e in evs] == [EventType.RDP_RECONNECT]


# ---------------------------------------------------------------- локализованный «LOCAL»
def test_localized_local_address_is_not_remote():
    from core.eventlog_monitor import is_remote_address
    for local in ("LOCAL", "ЛОКАЛЬНЫЕ", "Локальный", "LOKAL", "-", "", "127.0.0.1", "::1", "0.0.0.0", "::ffff:127.0.0.1"):
        assert not is_remote_address(local), local
    for remote in ("192.168.1.50", "10.0.0.7", "fe80::1%12", "2001:db8::5", "::ffff:10.1.2.3"):
        assert is_remote_address(remote), remote


def test_russian_lsm_local_logon_not_rdp():
    ev = map_event(raw(LSM_CHANNEL, 21, 1, T0, User="IMON\\Khilola.Mirzoeva", SessionID=1, Address="ЛОКАЛЬНЫЕ"))
    assert ev.event_type == EventType.LOCAL_LOGON and ev.ip == ""
    assert map_event(raw(LSM_CHANNEL, 22, 2, T0, User="x", SessionID=1, Address="ЛОКАЛЬНЫЕ")) is None
    assert map_event(raw(LSM_CHANNEL, 25, 3, T0, User="x", SessionID=1, Address="ЛОКАЛЬНЫЕ")) is None


def test_storage_migrates_wrong_local_records(tmp_path):
    from services.storage import Storage
    path = tmp_path / "h.db"
    st = Storage(path)
    st._conn.execute("DELETE FROM meta")
    bad = ConnectionEvent(T0, EventType.RDP_CONNECT, "Журнал LSM (ID 21)", Confidence.HIGH,
                          user="IMON\\x", ip="ЛОКАЛЬНЫЕ", session_id=1, key="evt:LSM:1")
    good = ConnectionEvent(T0, EventType.RDP_CONNECT, "Журнал LSM (ID 21)", Confidence.HIGH,
                           user="IMON\\y", ip="10.0.0.5", session_id=2, key="evt:LSM:2")
    st.add_event(bad)
    st.add_event(good)
    st._conn.commit()
    st.close()
    st = Storage(path)
    rows = {r.user: r for r in st.query()}
    assert rows["IMON\\x"].event_type == "local_logon" and rows["IMON\\x"].ip == ""
    assert rows["IMON\\y"].event_type == "rdp_connect"
    assert st.last_connection().user == "IMON\\y"
