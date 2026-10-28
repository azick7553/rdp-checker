"""Общие модели данных мониторинга.

Здесь нет зависимостей от Windows и Qt — модуль используется и в тестах на любой ОС.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


class SessionState(str, enum.Enum):
    """WTS_CONNECTSTATE_CLASS."""

    ACTIVE = "Active"
    CONNECTED = "Connected"
    CONNECT_QUERY = "ConnectQuery"
    SHADOW = "Shadow"
    DISCONNECTED = "Disconnected"
    IDLE = "Idle"
    LISTEN = "Listen"
    RESET = "Reset"
    DOWN = "Down"
    INIT = "Init"
    UNKNOWN = "Unknown"

    @classmethod
    def from_wts(cls, value: int) -> "SessionState":
        order = [
            cls.ACTIVE, cls.CONNECTED, cls.CONNECT_QUERY, cls.SHADOW, cls.DISCONNECTED,
            cls.IDLE, cls.LISTEN, cls.RESET, cls.DOWN, cls.INIT,
        ]
        if 0 <= value < len(order):
            return order[value]
        return cls.UNKNOWN


SESSION_STATE_RU = {
    SessionState.ACTIVE: "Активен",
    SessionState.CONNECTED: "Подключён",
    SessionState.CONNECT_QUERY: "Подключение",
    SessionState.SHADOW: "Теневой",
    SessionState.DISCONNECTED: "Отключён",
    SessionState.IDLE: "Ожидание",
    SessionState.LISTEN: "Прослушивание",
    SessionState.RESET: "Сброс",
    SessionState.DOWN: "Ошибка",
    SessionState.INIT: "Инициализация",
    SessionState.UNKNOWN: "Неизвестно",
}


class Protocol(str, enum.Enum):
    CONSOLE = "console"
    RDP = "rdp"
    ICA = "ica"
    UNKNOWN = "unknown"


class Confidence(enum.IntEnum):
    """Уровень достоверности. Чем больше — тем надёжнее."""

    INFO = 0       # справочная информация, не признак подключения
    LOW = 1        # единичный косвенный признак
    MEDIUM = 2     # признак из одного надёжного источника, без подтверждения
    HIGH = 3       # надёжный источник (журнал входа в RDP-сеанс и т.п.)
    CONFIRMED = 4  # наблюдается прямо сейчас через WTS API и/или подтверждено несколькими источниками

    @property
    def label(self) -> str:
        return CONFIDENCE_RU[self]


CONFIDENCE_RU = {
    Confidence.INFO: "Информация",
    Confidence.LOW: "Низкая",
    Confidence.MEDIUM: "Средняя",
    Confidence.HIGH: "Высокая",
    Confidence.CONFIRMED: "Подтверждено",
}


class EventType(str, enum.Enum):
    RDP_CONNECT = "rdp_connect"
    RDP_ACTIVE_AT_START = "rdp_active_at_start"
    RDP_RECONNECT = "rdp_reconnect"
    RDP_DISCONNECT = "rdp_disconnect"
    RDP_LOGOFF = "rdp_logoff"
    RDP_STATE_CHANGE = "rdp_state_change"
    RDP_AUTH = "rdp_auth"                # 1149: аутентификация, без подтверждения входа в сеанс
    RDP_SHELL_START = "rdp_shell_start"  # LSM 22
    SHADOW_START = "shadow_start"
    SHADOW_STOP = "shadow_stop"
    SHADOW_PERMISSION = "shadow_permission"
    SHADOW_SUSPECTED = "shadow_suspected"
    NETWORK_CONNECT = "network_connect"
    NETWORK_DISCONNECT = "network_disconnect"
    LOCAL_LOGON = "local_logon"
    LOCAL_LOGOFF = "local_logoff"
    REMOTE_TOOL_STARTED = "remote_tool_started"
    REMOTE_TOOL_STOPPED = "remote_tool_stopped"
    REMOTE_TOOL_INCOMING = "remote_tool_incoming"
    MISSED_WHILE_AWAY = "missed_while_away"
    MONITOR = "monitor"


EVENT_TYPE_RU = {
    EventType.RDP_CONNECT: "RDP-подключение",
    EventType.RDP_ACTIVE_AT_START: "Активный RDP-сеанс (при запуске)",
    EventType.RDP_RECONNECT: "Повторное RDP-подключение",
    EventType.RDP_DISCONNECT: "RDP-отключение",
    EventType.RDP_LOGOFF: "Завершение RDP-сеанса",
    EventType.RDP_STATE_CHANGE: "Изменение состояния сеанса",
    EventType.RDP_AUTH: "RDP-аутентификация",
    EventType.RDP_SHELL_START: "Запуск оболочки RDP-сеанса",
    EventType.SHADOW_START: "Теневое подключение: начало",
    EventType.SHADOW_STOP: "Теневое подключение: конец",
    EventType.SHADOW_PERMISSION: "Теневое подключение: разрешение",
    EventType.SHADOW_SUSPECTED: "Признаки теневого подключения",
    EventType.NETWORK_CONNECT: "TCP-соединение с RDP-портом",
    EventType.NETWORK_DISCONNECT: "TCP-соединение с RDP-портом закрыто",
    EventType.LOCAL_LOGON: "Локальный вход",
    EventType.LOCAL_LOGOFF: "Локальный выход",
    EventType.REMOTE_TOOL_STARTED: "Запущено средство удалённого доступа",
    EventType.REMOTE_TOOL_STOPPED: "Средство удалённого доступа остановлено",
    EventType.REMOTE_TOOL_INCOMING: "Входящее подключение (журнал программы)",
    EventType.MISSED_WHILE_AWAY: "События, пока сеанс был отключён",
    EventType.MONITOR: "Мониторинг",
}

# Типы, которые говорят о том, что кто-то вошёл / подключился
CONNECT_TYPES = {
    EventType.RDP_CONNECT, EventType.RDP_ACTIVE_AT_START, EventType.RDP_RECONNECT,
    EventType.RDP_SHELL_START, EventType.SHADOW_START,
}
DISCONNECT_TYPES = {
    EventType.RDP_DISCONNECT, EventType.RDP_LOGOFF, EventType.SHADOW_STOP,
}


class SourceState(str, enum.Enum):
    AVAILABLE = "available"
    PARTIAL = "partial"
    DENIED = "denied"
    ERROR = "error"


SOURCE_STATE_RU = {
    SourceState.AVAILABLE: "Доступно",
    SourceState.PARTIAL: "Частично доступно",
    SourceState.DENIED: "Нет доступа",
    SourceState.ERROR: "Ошибка",
}


class OverallStatus(str, enum.Enum):
    NO_CONNECTIONS = "green"     # источники доступны, удалённых подключений не обнаружено
    CONNECTED = "red"            # подтверждено активное удалённое подключение
    INSUFFICIENT = "yellow"      # недостаточно данных или есть неподтверждённые признаки
    STOPPED = "gray"             # мониторинг приостановлен


@dataclass
class SourceStatus:
    key: str
    title: str
    state: SourceState
    message: str = ""
    detail: str = ""

    @property
    def usable(self) -> bool:
        return self.state in (SourceState.AVAILABLE, SourceState.PARTIAL)


@dataclass
class SessionInfo:
    session_id: int
    winstation: str = ""
    state: SessionState = SessionState.UNKNOWN
    user: str = ""
    domain: str = ""
    client_name: str = ""
    client_ip: str = ""
    protocol: Protocol = Protocol.UNKNOWN
    connect_time: Optional[datetime] = None
    logon_time: Optional[datetime] = None
    disconnect_time: Optional[datetime] = None
    is_current: bool = False
    is_console: bool = False
    first_seen: Optional[datetime] = None
    source: str = "WTS API"
    query_errors: list[str] = field(default_factory=list)

    @property
    def is_listener(self) -> bool:
        return self.state == SessionState.LISTEN or self.session_id >= 65536

    @property
    def is_services(self) -> bool:
        return self.session_id == 0

    @property
    def is_remote(self) -> bool:
        """Сеанс подключён по RDP (а не локально с консоли)."""
        if self.is_listener or self.is_services:
            return False
        if self.protocol == Protocol.RDP:
            return True
        ws = (self.winstation or "").lower()
        return ws.startswith("rdp-tcp#") or ws.startswith("rdp-udp")

    @property
    def is_remote_live(self) -> bool:
        """Удалённый клиент подключён к сеансу прямо сейчас."""
        return self.is_remote and self.state in (
            SessionState.ACTIVE, SessionState.CONNECTED, SessionState.SHADOW, SessionState.CONNECT_QUERY,
        )

    @property
    def full_user(self) -> str:
        if self.domain and self.user:
            return f"{self.domain}\\{self.user}"
        return self.user

    @property
    def display_time(self) -> Optional[datetime]:
        return self.connect_time or self.logon_time or self.first_seen


@dataclass
class NetworkConnection:
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str
    pid: Optional[int] = None

    @property
    def key(self) -> str:
        return f"{self.remote_ip}:{self.remote_port}->{self.local_port}"

    @property
    def is_loopback(self) -> bool:
        return self.remote_ip.startswith("127.") or self.remote_ip in ("::1", "0:0:0:0:0:0:0:1")


class ToolConnectionStatus(str, enum.Enum):
    NOT_RUNNING = "not_running"
    UNKNOWN = "unknown"            # процесс запущен, но подключение определить нельзя
    EVIDENCE = "evidence"          # в журнале программы есть входящие подключения
    CONFIRMED = "confirmed"        # подтверждено (из процесса само по себе никогда не ставится)


TOOL_CONNECTION_RU = {
    ToolConnectionStatus.NOT_RUNNING: "—",
    ToolConnectionStatus.UNKNOWN: "Статус подключения неизвестен",
    ToolConnectionStatus.EVIDENCE: "Есть записи о входящих подключениях",
    ToolConnectionStatus.CONFIRMED: "Активное подключение подтверждено",
}


@dataclass
class RemoteToolStatus:
    key: str
    name: str
    category: str
    installed: bool = False
    install_path: str = ""
    running: bool = False
    processes: list[str] = field(default_factory=list)   # "name (PID 123, сеанс 1)"
    connection: ToolConnectionStatus = ToolConnectionStatus.NOT_RUNNING
    last_incoming: Optional[datetime] = None
    note: str = ""
    suspicious: bool = False   # признак, требующий внимания (например, компоненты теневого RDP)


@dataclass
class ConnectionEvent:
    timestamp: datetime
    event_type: EventType
    source: str
    confidence: Confidence
    user: str = ""
    ip: str = ""
    session_id: Optional[int] = None
    details: str = ""
    key: str = ""                # уникальный ключ для дедупликации в БД
    client_name: str = ""
    historical: bool = False     # событие из прошлого (загружено при старте) — без уведомления
    db_id: Optional[int] = None

    @property
    def type_label(self) -> str:
        return EVENT_TYPE_RU.get(self.event_type, self.event_type.value)

    @property
    def norm_user(self) -> str:
        return normalize_user(self.user)


def normalize_user(user: str) -> str:
    u = (user or "").strip().lower()
    if "\\" in u:
        u = u.split("\\", 1)[1]
    if "@" in u:
        u = u.split("@", 1)[0]
    return u


@dataclass
class CycleResult:
    """Результат одного цикла мониторинга, передаётся в GUI."""

    timestamp: datetime
    sessions: list[SessionInfo]
    network: list[NetworkConnection]
    remote_tools: list[RemoteToolStatus]
    sources: dict[str, SourceStatus]
    new_events: list[ConnectionEvent]
    notify_events: list[ConnectionEvent]
    overall: OverallStatus
    overall_title: str
    overall_reasons: list[str]
    current_session_id: Optional[int] = None
    current_session_remote: bool = False
    rdp_server_enabled: Optional[bool] = None
    rdp_port: int = 3389
    cycle_ms: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def remote_sessions(self) -> list[SessionInfo]:
        return [s for s in self.sessions if s.is_remote_live]
