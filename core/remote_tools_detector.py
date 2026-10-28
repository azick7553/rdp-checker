"""Обнаружение сторонних средств удалённого доступа.

ВАЖНО: наличие процесса НЕ означает, что кто-то подключён. Монитор никогда не помечает
подключение как подтверждённое только по факту запуска процесса. Память чужих процессов
не читается. Используются только список процессов (psutil), проверка наличия файлов и
текстовые журналы входящих подключений, которые программы сами ведут в доступных пользователю папках.
"""
from __future__ import annotations

import logging
import ntpath
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Iterable, Optional

from core import winapi
from core.models import (
    Confidence, ConnectionEvent, EventType, RemoteToolStatus, SourceState, SourceStatus, ToolConnectionStatus,
)

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ToolSpec:
    key: str
    name: str
    category: str
    processes: tuple[str, ...]
    paths: tuple[str, ...] = ()
    logs: tuple[str, ...] = ()
    log_format: str = ""
    suspicious_when_running: bool = False
    note: str = ""


PF = "%ProgramFiles%"
PF86 = "%ProgramFiles(x86)%"

TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("rdp_shadow", "Компоненты теневого RDP (Shadow)", "Встроенные средства Windows",
             ("rdpsa.exe", "rdpsaproxy.exe", "rdpsauachelper.exe"),
             suspicious_when_running=True,
             note="Эти процессы Windows запускает при теневом подключении (просмотре/управлении) к сеансу. "
                  "Это сильный признак, но не окончательное доказательство."),
    ToolSpec("quick_assist", "Быстрая помощь (Quick Assist)", "Встроенные средства Windows",
             ("quickassist.exe",),
             (r"%SystemRoot%\System32\quickassist.exe", r"%LOCALAPPDATA%\Microsoft\WindowsApps\quickassist.exe"),
             note="Процесс запущен у того, кто показывает экран, и у помощника. Сам факт запуска не означает сеанс."),
    ToolSpec("remote_assistance", "Удалённый помощник Windows (msra)", "Встроенные средства Windows",
             ("msra.exe", "raserver.exe"), (r"%SystemRoot%\System32\msra.exe",),
             note="raserver.exe запускается при предложении удалённой помощи на этом компьютере."),
    ToolSpec("anydesk", "AnyDesk", "Сторонние программы", ("anydesk.exe",),
             (PF86 + r"\AnyDesk\AnyDesk.exe", PF + r"\AnyDesk\AnyDesk.exe"),
             (r"%APPDATA%\AnyDesk\connection_trace.txt", r"%ProgramData%\AnyDesk\connection_trace.txt"),
             "anydesk"),
    ToolSpec("teamviewer", "TeamViewer", "Сторонние программы",
             ("teamviewer.exe", "teamviewer_service.exe", "tv_w32.exe", "tv_x64.exe"),
             (PF + r"\TeamViewer\TeamViewer.exe", PF86 + r"\TeamViewer\TeamViewer.exe"),
             (PF + r"\TeamViewer\Connections_incoming.txt", PF86 + r"\TeamViewer\Connections_incoming.txt"),
             "teamviewer"),
    ToolSpec("rustdesk", "RustDesk", "Сторонние программы", ("rustdesk.exe",),
             (PF + r"\RustDesk\rustdesk.exe",)),
    ToolSpec("chrome_rd", "Удалённый рабочий стол Chrome", "Сторонние программы",
             ("remoting_host.exe", "remoting_desktop.exe", "remoting_native_messaging_host.exe"),
             (PF86 + r"\Google\Chrome Remote Desktop", PF + r"\Google\Chrome Remote Desktop")),
    ToolSpec("vnc", "VNC (RealVNC / TightVNC / UltraVNC / TigerVNC)", "Сторонние программы",
             ("winvnc.exe", "winvnc4.exe", "tvnserver.exe", "vncserver.exe", "uvnc_service.exe", "vncviewer.exe"),
             (PF + r"\RealVNC", PF + r"\TightVNC", PF + r"\uvnc bvba\UltraVNC", PF + r"\TigerVNC")),
    ToolSpec("sccm", "Configuration Manager Remote Control", "Корпоративные средства",
             ("cmrcservice.exe",), (r"%SystemRoot%\CCM\RemCtrl",),
             note="Корпоративная служба удалённого управления. Обычно работает постоянно; "
                  "во время сеанса Windows показывает панель уведомления, если это не отключено политикой."),
    ToolSpec("screenconnect", "ConnectWise ScreenConnect", "Корпоративные средства",
             ("screenconnect.clientservice.exe", "screenconnect.windowsclient.exe")),
    ToolSpec("splashtop", "Splashtop", "Сторонние программы", ("srservice.exe", "srmanager.exe", "strwinclt.exe")),
    ToolSpec("logmein", "LogMeIn / GoTo Resolve", "Сторонние программы", ("logmein.exe", "lmi_rescue.exe", "gotoassist.exe")),
    ToolSpec("radmin", "Radmin", "Сторонние программы", ("rserver3.exe",)),
    ToolSpec("ammyy", "Ammyy Admin", "Сторонние программы", ("aa_v3.exe", "ammyy_admin.exe")),
    ToolSpec("aeroadmin", "AeroAdmin", "Сторонние программы", ("aeroadmin.exe",)),
    ToolSpec("supremo", "Supremo", "Сторонние программы", ("supremo.exe", "supremoservice.exe")),
    ToolSpec("zoho", "Zoho Assist", "Сторонние программы", ("zaservice.exe", "zohotray.exe")),
    ToolSpec("dameware", "DameWare Mini Remote Control", "Корпоративные средства", ("dwrcs.exe",)),
    ToolSpec("nomachine", "NoMachine", "Сторонние программы", ("nxservice.exe", "nxserver.exe", "nxnode.exe")),
    ToolSpec("parsec", "Parsec", "Сторонние программы", ("parsecd.exe",)),
)


@dataclass
class IncomingRecord:
    tool_key: str
    start: datetime
    partner: str = ""
    end: Optional[datetime] = None
    local_user: str = ""
    kind: str = ""


# ====================================================================== log parsers
_TV_DT = ("%d-%m-%Y %H:%M:%S", "%d.%m.%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S")


def _parse_dt(value: str, formats: Iterable[str]) -> Optional[datetime]:
    value = value.strip()
    for fmt in formats:
        try:
            return datetime.strptime(value, fmt).astimezone()
        except ValueError:
            continue
    return None


def parse_teamviewer_incoming(text: str) -> list[IncomingRecord]:
    """Connections_incoming.txt: ID<TAB>Имя<TAB>Начало<TAB>Конец<TAB>Пользователь<TAB>Тип<TAB>GUID."""
    out = []
    for line in text.splitlines():
        parts = [p.strip() for p in line.split("\t")]
        if len(parts) < 4:
            continue
        start = _parse_dt(parts[2], _TV_DT)
        if not start:
            continue
        out.append(IncomingRecord(
            "teamviewer", start, partner=f"{parts[1]} (ID {parts[0]})".strip(),
            end=_parse_dt(parts[3], _TV_DT), local_user=parts[4] if len(parts) > 4 else "",
            kind=parts[5] if len(parts) > 5 else "",
        ))
    return out


_AD_RE = re.compile(r"^\s*Incoming\s+(\d{4}-\d{2}-\d{2}),?\s+(\d{1,2}:\d{2}(?::\d{2})?)\s+(\S+)?\s*(\d+)?", re.IGNORECASE)


def parse_anydesk_trace(text: str) -> list[IncomingRecord]:
    """connection_trace.txt: «Incoming  2026-10-28, 14:32  User  123456789  123456789»."""
    out = []
    for line in text.splitlines():
        m = _AD_RE.match(line)
        if not m:
            continue
        t = m.group(2)
        start = _parse_dt(f"{m.group(1)} {t}", ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"))
        if not start:
            continue
        out.append(IncomingRecord("anydesk", start, partner=f"ID {m.group(4)}" if m.group(4) else "",
                                  kind=m.group(3) or ""))
    return out


def read_text_tail(path: str, max_bytes: int = 128 * 1024) -> str:
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - max_bytes))
        data = f.read()
    if data.startswith(b"\xff\xfe") or (len(data) > 2 and data[1:2] == b"\x00"):
        return data.decode("utf-16-le", errors="replace")
    for enc in ("utf-8", "cp1251"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


# ====================================================================== detector
ProcFunc = Callable[[], list[tuple[int, str, Optional[str]]]]


def _psutil_processes() -> list[tuple[int, str, Optional[str]]]:
    import psutil
    out = []
    for p in psutil.process_iter(["pid", "name", "username"]):
        try:
            info = p.info
            out.append((info["pid"], info.get("name") or "", info.get("username")))
        except Exception:  # noqa: BLE001
            continue
    return out


class RemoteToolsDetector:
    def __init__(self, process_func: Optional[ProcFunc] = None, exists_func: Callable[[str], bool] = os.path.exists,
                 read_func: Callable[[str], str] = read_text_tail, mtime_func: Callable[[str], float] = os.path.getmtime,
                 session_func: Callable[[int], Optional[int]] = winapi.process_session_id,
                 tools: tuple[ToolSpec, ...] = TOOLS, history_days: int = 30) -> None:
        self._procs = process_func or _psutil_processes
        self._exists = exists_func
        self._read = read_func
        self._mtime = mtime_func
        self._session = session_func
        self.tools = tools
        self.history_days = history_days
        self._installed_cache: dict[str, str] = {}
        self._installed_checked: Optional[datetime] = None
        self._log_cache: dict[str, tuple[float, list[IncomingRecord]]] = {}
        self._seen_records: set[str] = set()
        self._prev_running: dict[str, set[str]] = {}
        self._initialized = False
        self.status = SourceStatus("procs", "Список процессов", SourceState.AVAILABLE, "")
        self.last: list[RemoteToolStatus] = []

    def _expand(self, path: str) -> str:
        return ntpath.expandvars(path)  # формат %VAR% одинаково на любой ОС (для тестов)

    def _check_installed(self, now: datetime) -> None:
        if self._installed_checked and now - self._installed_checked < timedelta(minutes=10):
            return
        self._installed_checked = now
        cache = {}
        for t in self.tools:
            for p in t.paths:
                ep = self._expand(p)
                if "%" in ep:
                    continue
                try:
                    if self._exists(ep):
                        cache[t.key] = ep
                        break
                except OSError:
                    continue
        self._installed_cache = cache

    def _read_logs(self, t: ToolSpec) -> list[IncomingRecord]:
        records: list[IncomingRecord] = []
        for p in t.logs:
            ep = self._expand(p)
            if "%" in ep:
                continue
            try:
                if not self._exists(ep):
                    continue
                mtime = self._mtime(ep)
                cached = self._log_cache.get(ep)
                if cached and cached[0] == mtime:
                    records.extend(cached[1])
                    continue
                text = self._read(ep)
            except OSError:
                continue
            parsed: list[IncomingRecord] = []
            if t.log_format == "teamviewer":
                parsed = parse_teamviewer_incoming(text)
            elif t.log_format == "anydesk":
                parsed = parse_anydesk_trace(text)
            self._log_cache[ep] = (mtime, parsed)
            records.extend(parsed)
        return records

    def scan(self, now: Optional[datetime] = None, current_session: Optional[int] = None) -> tuple[list[RemoteToolStatus], list[ConnectionEvent]]:
        now = now or datetime.now().astimezone()
        self._check_installed(now)
        try:
            procs = self._procs()
            self.status = SourceStatus("procs", "Список процессов", SourceState.AVAILABLE, f"Процессов: {len(procs)}")
        except Exception as e:  # noqa: BLE001
            self.status = SourceStatus("procs", "Список процессов", SourceState.ERROR, "Не удалось получить список процессов", str(e))
            procs = []
        by_name: dict[str, list[tuple[int, Optional[str]]]] = {}
        for pid, name, user in procs:
            by_name.setdefault(name.lower(), []).append((pid, user))

        statuses: list[RemoteToolStatus] = []
        events: list[ConnectionEvent] = []
        for t in self.tools:
            st = RemoteToolStatus(t.key, t.name, t.category, note=t.note)
            if t.key in self._installed_cache:
                st.installed = True
                st.install_path = self._installed_cache[t.key]
            running_names: set[str] = set()
            for pname in t.processes:
                for pid, user in by_name.get(pname, []):
                    sid = None
                    try:
                        sid = self._session(pid)
                    except Exception:  # noqa: BLE001
                        pass
                    where = f"PID {pid}" + (f", сеанс {sid}" if sid is not None else "")
                    if sid is not None and current_session is not None and sid == current_session:
                        where += " — ваш сеанс"
                    if user:
                        where += f", {user}"
                    st.processes.append(f"{pname} ({where})")
                    running_names.add(pname)
            st.running = bool(running_names)
            if st.running:
                st.installed = True
                st.connection = ToolConnectionStatus.UNKNOWN
                st.suspicious = t.suspicious_when_running

            # журналы входящих подключений
            if t.logs:
                records = self._read_logs(t)
                cutoff = now - timedelta(days=self.history_days)
                recent = [r for r in records if r.start >= cutoff]
                if recent:
                    st.last_incoming = max(r.start for r in recent)
                    if st.connection != ToolConnectionStatus.CONFIRMED:
                        st.connection = ToolConnectionStatus.EVIDENCE
                for r in recent:
                    k = f"tool:{t.key}:{r.start.timestamp():.0f}:{r.partner}"
                    if k in self._seen_records:
                        continue
                    self._seen_records.add(k)
                    period = f"{r.start:%d.%m.%Y %H:%M}" + (f" – {r.end:%H:%M}" if r.end else "")
                    events.append(ConnectionEvent(
                        timestamp=r.start, event_type=EventType.REMOTE_TOOL_INCOMING, source=f"Журнал {t.name}",
                        confidence=Confidence.MEDIUM, user=r.local_user,
                        details=f"{t.name}: входящее подключение {r.partner} ({period}) {r.kind}".strip(),
                        key=k, historical=not self._initialized,
                    ))

            prev = self._prev_running.get(t.key, set())
            if running_names and not prev:
                if t.suspicious_when_running:
                    events.append(ConnectionEvent(
                        timestamp=now, event_type=EventType.SHADOW_SUSPECTED, source="Список процессов",
                        confidence=Confidence.MEDIUM, session_id=current_session,
                        details=f"Запущены процессы: {', '.join(sorted(running_names))}. {t.note}",
                        key=f"proc:{t.key}:start:{now.timestamp():.0f}",
                    ))
                else:
                    events.append(ConnectionEvent(
                        timestamp=now, event_type=EventType.REMOTE_TOOL_STARTED, source="Список процессов",
                        confidence=Confidence.INFO,
                        details=(f"{t.name}: процесс запущен ({', '.join(sorted(running_names))})"
                                 + (" — уже работал при запуске монитора" if not self._initialized else "")
                                 + ". Наличие процесса не означает активного подключения."),
                        key=f"proc:{t.key}:start:{now.timestamp():.0f}",
                    ))
            elif prev and not running_names:
                events.append(ConnectionEvent(
                    timestamp=now, event_type=EventType.REMOTE_TOOL_STOPPED, source="Список процессов",
                    confidence=Confidence.INFO, details=f"{t.name}: процессы завершены.",
                    key=f"proc:{t.key}:stop:{now.timestamp():.0f}",
                ))
            self._prev_running[t.key] = running_names
            statuses.append(st)

        self._initialized = True
        statuses.sort(key=lambda s: (not s.suspicious, not s.running, not s.installed, s.category, s.name))
        self.last = statuses
        return statuses, events
