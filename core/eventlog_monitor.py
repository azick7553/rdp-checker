"""Чтение журналов Windows через wevtapi.dll (ctypes, без pywin32).

Журналы и события:
  * Microsoft-Windows-TerminalServices-LocalSessionManager/Operational — 21, 22, 23, 24, 25, 39
  * Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational — 1149, 261, 20503–20513 (теневые сеансы)
  * Security — 4624/4634 (LogonType 10/12), 4647, 4778, 4779

Доступ к Security обычно есть только у администраторов и группы «Event Log Readers».
Журналы TerminalServices/Operational, как правило, читаемы интерактивными пользователями,
но в организации это может быть изменено. Каждый журнал проверяется отдельно.
"""
from __future__ import annotations

import ctypes
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Optional

from core import winapi
from core.models import Confidence, ConnectionEvent, EventType, SourceState, SourceStatus

log = logging.getLogger(__name__)

LSM_CHANNEL = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
RCM_CHANNEL = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
SECURITY_CHANNEL = "Security"

CHANNEL_SHORT = {LSM_CHANNEL: "LSM", RCM_CHANNEL: "RCM", SECURITY_CHANNEL: "Security"}
CHANNEL_TITLE = {
    LSM_CHANNEL: "Журнал TerminalServices-LocalSessionManager",
    RCM_CHANNEL: "Журнал TerminalServices-RemoteConnectionManager",
    SECURITY_CHANNEL: "Журнал безопасности (Security)",
}

SHADOW_START_IDS = {20503, 20506}
SHADOW_STOP_IDS = {20504, 20507}
SHADOW_PERMISSION_IDS = {20505, 20508, 20509, 20510, 20511, 20512, 20513}

LOCAL_ADDRESSES = {"", "local", "-", "локальный", "127.0.0.1", "::1"}

_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


@dataclass
class RawEvent:
    channel: str
    event_id: int
    record_id: int
    time: datetime
    provider: str = ""
    data: dict[str, str] = field(default_factory=dict)
    message: str = ""


# ====================================================================== parsing
def parse_event_xml(xml: str, channel: str = "") -> Optional[RawEvent]:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    system = root.find(f"{_NS}System")
    if system is None:
        return None
    try:
        event_id = int((system.findtext(f"{_NS}EventID") or "0").strip())
        record_id = int((system.findtext(f"{_NS}EventRecordID") or "0").strip())
    except ValueError:
        return None
    tc = system.find(f"{_NS}TimeCreated")
    ts_raw = tc.get("SystemTime") if tc is not None else None
    ts = _parse_system_time(ts_raw) or datetime.now().astimezone()
    prov = system.find(f"{_NS}Provider")
    provider = prov.get("Name", "") if prov is not None else ""
    ch = system.findtext(f"{_NS}Channel") or channel

    data: dict[str, str] = {}
    ed = root.find(f"{_NS}EventData")
    if ed is not None:
        for d in ed:
            name = d.get("Name")
            if name:
                data[name] = (d.text or "").strip()
    ud = root.find(f"{_NS}UserData")
    if ud is not None:
        for el in ud.iter():
            if el is ud or len(el):
                continue
            local = el.tag.split("}", 1)[-1]
            data.setdefault(local, (el.text or "").strip())
    return RawEvent(ch, event_id, record_id, ts, provider, data)


def _parse_system_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    v = value.strip().replace("Z", "+00:00")
    # Windows отдаёт до 7–9 знаков дробной части — Python понимает максимум 6
    if "." in v:
        head, rest = v.split(".", 1)
        frac = "".join(ch for ch in rest if ch.isdigit())
        tz = rest[len(frac):]
        v = f"{head}.{frac[:6].ljust(6, '0')}{tz}"
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        from datetime import timezone
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone()


def _is_remote_address(addr: str) -> bool:
    return (addr or "").strip().lower() not in LOCAL_ADDRESSES


def _user(domain: str, user: str) -> str:
    user = (user or "").strip()
    domain = (domain or "").strip()
    if user in ("-", ""):
        return ""
    return f"{domain}\\{user}" if domain and domain != "-" and "\\" not in user else user


def _int(v: Optional[str]) -> Optional[int]:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def map_event(raw: RawEvent) -> Optional[ConnectionEvent]:
    """Преобразование записи журнала в событие монитора. None — событие не относится к удалённому доступу."""
    d = raw.data
    short = CHANNEL_SHORT.get(raw.channel, raw.channel)
    src = f"Журнал {short} (ID {raw.event_id})"
    base = dict(timestamp=raw.time, source=src, key=f"evt:{short}:{raw.record_id}")
    msg = (" " + raw.message.strip().replace("\r", " ").replace("\n", " ")) if raw.message else ""

    if raw.channel == LSM_CHANNEL:
        user = d.get("User", "")
        addr = d.get("Address", "")
        sid = _int(d.get("SessionID"))
        remote = _is_remote_address(addr)
        ip = addr if remote else ""
        eid = raw.event_id
        if eid == 21:
            if remote:
                return ConnectionEvent(event_type=EventType.RDP_CONNECT, confidence=Confidence.HIGH, user=user, ip=ip,
                                       session_id=sid, details="Вход в сеанс по RDP выполнен успешно." + msg, **base)
            return ConnectionEvent(event_type=EventType.LOCAL_LOGON, confidence=Confidence.INFO, user=user,
                                   session_id=sid, details="Локальный вход в сеанс." + msg, **base)
        if eid == 22 and remote:
            return ConnectionEvent(event_type=EventType.RDP_SHELL_START, confidence=Confidence.HIGH, user=user, ip=ip,
                                   session_id=sid, details="Запущена оболочка (рабочий стол) RDP-сеанса." + msg, **base)
        if eid == 23:
            return ConnectionEvent(event_type=EventType.LOCAL_LOGOFF, confidence=Confidence.INFO, user=user,
                                   session_id=sid, details="Выход из сеанса." + msg, **base)
        if eid == 24 and remote:
            return ConnectionEvent(event_type=EventType.RDP_DISCONNECT, confidence=Confidence.HIGH, user=user, ip=ip,
                                   session_id=sid, details="RDP-клиент отключился от сеанса." + msg, **base)
        if eid == 25 and remote:
            return ConnectionEvent(event_type=EventType.RDP_RECONNECT, confidence=Confidence.HIGH, user=user, ip=ip,
                                   session_id=sid, details="Повторное RDP-подключение к сеансу." + msg, **base)
        if eid == 39:
            target, by = d.get("TargetSession", "?"), d.get("Source", "?")
            return ConnectionEvent(event_type=EventType.RDP_STATE_CHANGE, confidence=Confidence.INFO,
                                   session_id=_int(target),
                                   details=f"Сеанс {target} отключён сеансом {by}." + msg, **base)
        return None

    if raw.channel == RCM_CHANNEL:
        eid = raw.event_id
        if eid == 1149:
            user = _user(d.get("Param2", ""), d.get("Param1", ""))
            return ConnectionEvent(
                event_type=EventType.RDP_AUTH, confidence=Confidence.LOW, user=user, ip=d.get("Param3", ""),
                details="Успешная сетевая аутентификация RDP. Само по себе не доказывает вход в рабочий стол." + msg,
                **base)
        if eid == 261:
            return ConnectionEvent(event_type=EventType.NETWORK_CONNECT, confidence=Confidence.LOW,
                                   details="Слушатель RDP-Tcp принял входящее соединение." + msg, **base)
        if eid in SHADOW_START_IDS or eid in SHADOW_STOP_IDS or eid in SHADOW_PERMISSION_IDS:
            etype = (EventType.SHADOW_START if eid in SHADOW_START_IDS
                     else EventType.SHADOW_STOP if eid in SHADOW_STOP_IDS else EventType.SHADOW_PERMISSION)
            user = d.get("Param1", "") or d.get("User", "")
            sid = _int(d.get("Param2") or d.get("SessionID"))
            return ConnectionEvent(event_type=etype, confidence=Confidence.HIGH, user=user, session_id=sid,
                                   details="Событие теневого подключения (RDP Shadow) к сеансу." + msg, **base)
        return None

    if raw.channel == SECURITY_CHANNEL:
        eid = raw.event_id
        if eid in (4624, 4634):
            ltype = _int(d.get("LogonType"))
            if ltype not in (10, 12):
                return None
            user = _user(d.get("TargetDomainName", ""), d.get("TargetUserName", ""))
            if eid == 4624:
                ip = d.get("IpAddress", "")
                ip = "" if ip in ("-", "::1", "127.0.0.1") else ip
                return ConnectionEvent(event_type=EventType.RDP_CONNECT, confidence=Confidence.HIGH, user=user, ip=ip,
                                       client_name=d.get("WorkstationName", ""),
                                       details=f"Успешный вход, тип {ltype} (RemoteInteractive)." + msg, **base)
            return ConnectionEvent(event_type=EventType.RDP_LOGOFF, confidence=Confidence.HIGH, user=user,
                                   details=f"Выход, тип входа {ltype} (RemoteInteractive)." + msg, **base)
        if eid == 4647:
            user = _user(d.get("TargetDomainName", ""), d.get("TargetUserName", ""))
            return ConnectionEvent(event_type=EventType.LOCAL_LOGOFF, confidence=Confidence.INFO, user=user,
                                   details="Выход, инициированный пользователем (тип входа не указан)." + msg, **base)
        if eid in (4778, 4779):
            user = _user(d.get("AccountDomain", ""), d.get("AccountName", ""))
            addr = d.get("ClientAddress", "")
            session_name = d.get("SessionName", "")
            remote = _is_remote_address(addr) or session_name.lower().startswith("rdp-tcp")
            if not remote:
                return None  # быстрое переключение пользователей на консоли
            etype = EventType.RDP_RECONNECT if eid == 4778 else EventType.RDP_DISCONNECT
            text = "Повторное подключение к сеансу" if eid == 4778 else "Отключение от сеанса"
            return ConnectionEvent(event_type=etype, confidence=Confidence.HIGH, user=user,
                                   ip=addr if _is_remote_address(addr) else "", client_name=d.get("ClientName", ""),
                                   details=f"{text} ({session_name})." + msg, **base)
        return None
    return None


# ====================================================================== wevtapi
class EventLogAccessError(Exception):
    def __init__(self, channel: str, code: int, text: str = ""):
        self.channel = channel
        self.code = code
        super().__init__(text or f"{channel}: error {code}")

    @property
    def denied(self) -> bool:
        return self.code == winapi.ERROR_ACCESS_DENIED

    @property
    def not_found(self) -> bool:
        return self.code == winapi.ERROR_EVT_CHANNEL_NOT_FOUND


QueryFunc = Callable[[str, str, bool, int], list[RawEvent]]


if winapi.IS_WINDOWS:  # pragma: no cover - Windows only
    from ctypes import wintypes

    _wevt = ctypes.WinDLL("wevtapi", use_last_error=True)
    EVT_HANDLE = ctypes.c_void_p
    _wevt.EvtQuery.argtypes = [EVT_HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    _wevt.EvtQuery.restype = EVT_HANDLE
    _wevt.EvtNext.argtypes = [EVT_HANDLE, wintypes.DWORD, ctypes.POINTER(EVT_HANDLE), wintypes.DWORD,
                              wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    _wevt.EvtNext.restype = wintypes.BOOL
    _wevt.EvtRender.argtypes = [EVT_HANDLE, EVT_HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]
    _wevt.EvtRender.restype = wintypes.BOOL
    _wevt.EvtClose.argtypes = [EVT_HANDLE]
    _wevt.EvtClose.restype = wintypes.BOOL
    _wevt.EvtOpenPublisherMetadata.argtypes = [EVT_HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    _wevt.EvtOpenPublisherMetadata.restype = EVT_HANDLE
    _wevt.EvtFormatMessage.argtypes = [EVT_HANDLE, EVT_HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                       wintypes.DWORD, wintypes.DWORD, ctypes.c_wchar_p, ctypes.POINTER(wintypes.DWORD)]
    _wevt.EvtFormatMessage.restype = wintypes.BOOL

    EvtQueryChannelPath = 0x1
    EvtQueryForwardDirection = 0x100
    EvtQueryReverseDirection = 0x200
    EvtRenderEventXml = 1
    EvtFormatMessageEvent = 1

    _publisher_cache: dict[str, Optional[int]] = {}

    def _render_xml(h) -> str:
        used = wintypes.DWORD(0)
        props = wintypes.DWORD(0)
        _wevt.EvtRender(None, h, EvtRenderEventXml, 0, None, ctypes.byref(used), ctypes.byref(props))
        size = used.value
        if size == 0:
            return ""
        buf = ctypes.create_string_buffer(size)
        if not _wevt.EvtRender(None, h, EvtRenderEventXml, size, buf, ctypes.byref(used), ctypes.byref(props)):
            return ""
        return buf.raw[:used.value].decode("utf-16-le", errors="ignore").rstrip("\x00")

    def _format_message(provider: str, h) -> str:
        if not provider:
            return ""
        meta = _publisher_cache.get(provider, -1)
        if meta == -1:
            meta = _wevt.EvtOpenPublisherMetadata(None, provider, None, 0, 0) or None
            _publisher_cache[provider] = meta
        if not meta:
            return ""
        used = wintypes.DWORD(0)
        _wevt.EvtFormatMessage(meta, h, 0, 0, None, EvtFormatMessageEvent, 0, None, ctypes.byref(used))
        if not used.value:
            return ""
        buf = ctypes.create_unicode_buffer(used.value)
        if not _wevt.EvtFormatMessage(meta, h, 0, 0, None, EvtFormatMessageEvent, used.value, buf, ctypes.byref(used)):
            return ""
        return buf.value

    def wevt_query(channel: str, xpath: str, reverse: bool, limit: int, with_message: bool = True) -> list[RawEvent]:
        flags = EvtQueryChannelPath | (EvtQueryReverseDirection if reverse else EvtQueryForwardDirection)
        hq = _wevt.EvtQuery(None, channel, xpath, flags)
        if not hq:
            raise EventLogAccessError(channel, ctypes.get_last_error())
        out: list[RawEvent] = []
        try:
            arr = (EVT_HANDLE * 32)()
            returned = wintypes.DWORD(0)
            while len(out) < limit:
                want = max(1, min(32, limit - len(out)))
                if not _wevt.EvtNext(hq, want, arr, 1000, 0, ctypes.byref(returned)):
                    err = ctypes.get_last_error()
                    if err in (winapi.ERROR_NO_MORE_ITEMS, 0, 1460):  # 1460 = ERROR_TIMEOUT
                        break
                    raise EventLogAccessError(channel, err)
                for i in range(returned.value):
                    h = arr[i]
                    try:
                        if len(out) >= limit:
                            continue
                        xml = _render_xml(h)
                        raw = parse_event_xml(xml, channel)
                        if raw is not None:
                            if with_message:
                                try:
                                    raw.message = _format_message(raw.provider, h)[:600]
                                except Exception:
                                    pass
                            out.append(raw)
                    except Exception:  # noqa: BLE001 — одна битая запись не должна оставлять дескрипторы открытыми
                        log.debug("Failed to render event", exc_info=True)
                    finally:
                        _wevt.EvtClose(h)
        finally:
            _wevt.EvtClose(hq)
        return out
else:
    def wevt_query(channel: str, xpath: str, reverse: bool, limit: int, with_message: bool = True) -> list[RawEvent]:
        raise winapi.WinApiUnavailable("Журналы событий доступны только в Windows")


# ====================================================================== monitor
@dataclass
class ChannelQuery:
    channel: str
    system_filter: str        # условие для System[...]
    extra: str = ""           # дополнительное условие (EventData)


DEFAULT_QUERIES = [
    ChannelQuery(LSM_CHANNEL, "(EventID=21 or EventID=22 or EventID=23 or EventID=24 or EventID=25 or EventID=39)"),
    ChannelQuery(RCM_CHANNEL, "(EventID=1149 or EventID=261 or (EventID>=20503 and EventID<=20513))"),
    ChannelQuery(SECURITY_CHANNEL, "(EventID=4624 or EventID=4634)",
                 " and EventData[Data[@Name='LogonType']='10' or Data[@Name='LogonType']='12']"),
    ChannelQuery(SECURITY_CHANNEL, "(EventID=4647 or EventID=4778 or EventID=4779)"),
]


def build_xpath(q: ChannelQuery, after_record: Optional[int], lookback_ms: Optional[int]) -> str:
    cond = q.system_filter
    if after_record is not None:
        cond += f" and EventRecordID > {after_record}"
    if lookback_ms is not None:
        cond += f" and TimeCreated[timediff(@SystemTime) <= {lookback_ms}]"
    return f"*[System[{cond}]{q.extra}]"


class EventLogMonitor:
    def __init__(self, lookback_days: int = 7, query_func: Optional[QueryFunc] = None,
                 queries: Optional[list[ChannelQuery]] = None, include_security: bool = True) -> None:
        self.lookback_days = lookback_days
        self._query = query_func or (lambda ch, xp, rev, lim: wevt_query(ch, xp, rev, lim))
        self.queries = list(queries or DEFAULT_QUERIES)
        if not include_security:
            self.queries = [q for q in self.queries if q.channel != SECURITY_CHANNEL]
        self._last_record: dict[str, int] = {}
        self._status: dict[str, SourceStatus] = {}
        self._retry_after: dict[str, datetime] = {}
        self._empty_polls: dict[str, int] = {}
        self.started_at = datetime.now().astimezone()

    @property
    def channels(self) -> list[str]:
        seen: list[str] = []
        for q in self.queries:
            if q.channel not in seen:
                seen.append(q.channel)
        return seen

    def statuses(self) -> dict[str, SourceStatus]:
        return dict(self._status)

    def _set_status(self, channel: str, state: SourceState, message: str, detail: str = "") -> None:
        self._status[f"evt:{CHANNEL_SHORT.get(channel, channel)}"] = SourceStatus(
            f"evt:{CHANNEL_SHORT.get(channel, channel)}", CHANNEL_TITLE.get(channel, channel), state, message, detail,
        )

    @staticmethod
    def explain_error(channel: str, err: Exception) -> tuple[SourceState, str]:
        if isinstance(err, EventLogAccessError):
            if err.denied:
                if channel == SECURITY_CHANNEL:
                    return SourceState.DENIED, ("Windows не разрешает обычному пользователю просматривать Security Event Log. "
                                                "Мониторинг продолжится через доступные источники.")
                return SourceState.DENIED, "Нет прав на чтение этого журнала. Мониторинг продолжится через доступные источники."
            if err.not_found:
                return SourceState.ERROR, "Журнал не найден в этой системе."
            return SourceState.ERROR, f"Ошибка чтения журнала (код {err.code})."
        if isinstance(err, winapi.WinApiUnavailable):
            return SourceState.ERROR, "Журналы событий Windows доступны только в Windows."
        return SourceState.ERROR, f"Ошибка: {err}"

    def _check_cleared(self, ch: str) -> None:
        """Журнал очищен → номера записей начинаются заново; сбрасываем курсор, чтобы не пропустить новые события."""
        n = self._empty_polls.get(ch, 0) + 1
        self._empty_polls[ch] = n
        if n % 20:
            return
        try:
            latest = self._query(ch, "*", True, 1)
        except Exception:  # noqa: BLE001
            return
        newest = latest[0].record_id if latest else 0
        if newest < self._last_record.get(ch, 0):
            log.info("Event log %s appears to be cleared (newest %d < cursor %d)", ch, newest, self._last_record[ch])
            self._last_record[ch] = 0

    def poll(self, now: Optional[datetime] = None) -> list[ConnectionEvent]:
        """Один проход по всем журналам. Ошибки одного журнала не мешают остальным."""
        now = now or datetime.now().astimezone()
        events: list[ConnectionEvent] = []
        failed: set[str] = set()
        new_max: dict[str, int] = {}
        first_run_channels: set[str] = set()
        for q in self.queries:
            ch = q.channel
            if ch in failed:
                continue
            retry = self._retry_after.get(ch)
            if retry and now < retry:
                continue
            first = ch not in self._last_record
            if first:
                first_run_channels.add(ch)
            try:
                if first:
                    xp = build_xpath(q, None, self.lookback_days * 86_400_000)
                    raws = self._query(ch, xp, True, 500)
                    raws.reverse()
                else:
                    xp = build_xpath(q, self._last_record[ch], None)
                    raws = self._query(ch, xp, False, 1000)
                    if not raws:
                        self._check_cleared(ch)
            except Exception as e:  # noqa: BLE001 — любой сбой журнала не должен ронять монитор
                failed.add(ch)
                state, message = self.explain_error(ch, e)
                self._set_status(ch, state, message, str(e))
                # недоступный журнал перепроверяем редко, временные ошибки — чаще
                delay = 600 if state == SourceState.DENIED else 60
                self._retry_after[ch] = now + timedelta(seconds=delay)
                log.info("Event log %s unavailable: %s", ch, e)
                continue
            self._retry_after.pop(ch, None)
            for raw in raws:
                new_max[ch] = max(new_max.get(ch, self._last_record.get(ch, 0)), raw.record_id)
                ev = map_event(raw)
                if ev is None:
                    continue
                ev.historical = ev.timestamp < self.started_at - timedelta(seconds=60)
                events.append(ev)
            self._set_status(ch, SourceState.AVAILABLE, "Журнал доступен для чтения")
        for ch in first_run_channels - failed:
            if ch not in new_max:
                # в окне просмотра событий нет — запоминаем номер последней записи журнала,
                # чтобы при следующем опросе не перечитывать старые события
                try:
                    latest = self._query(ch, "*", True, 1)
                    new_max[ch] = latest[0].record_id if latest else 0
                except Exception:  # noqa: BLE001
                    new_max[ch] = 0
        for ch, rec in new_max.items():
            if ch not in failed:
                self._last_record[ch] = max(rec, self._last_record.get(ch, 0))
        events.sort(key=lambda e: e.timestamp)
        return events
