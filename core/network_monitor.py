"""Сетевые признаки RDP: настройки сервера RDP (только чтение) и TCP-соединения с RDP-портом.

* Реестр HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server — чтение разрешено пользователям.
  Ничего не изменяется.
* Таблица TCP-соединений (GetExtendedTcpTable через psutil) доступна без прав администратора.
  Установленное соединение с локальным RDP-портом означает, что к компьютеру подключён RDP-клиент
  (или идёт попытка входа). IP-адрес удалённой стороны виден даже тогда, когда WTS его не отдаёт.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional

from core import winapi
from core.models import Confidence, ConnectionEvent, EventType, NetworkConnection, SourceState, SourceStatus

log = logging.getLogger(__name__)

TS_KEY = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
RDP_TCP_KEY = TS_KEY + r"\WinStations\RDP-Tcp"
TS_POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"


@dataclass
class RdpServerConfig:
    enabled: Optional[bool] = None       # None — не удалось прочитать
    port: int = 3389
    policy_enabled: Optional[bool] = None
    shadow_policy: Optional[int] = None  # 0..4, см. документацию политики «Shadow»
    error: str = ""

    @property
    def shadow_description(self) -> str:
        return {
            None: "не задана политикой",
            0: "теневое подключение запрещено",
            1: "полный контроль с разрешения пользователя",
            2: "полный контроль без разрешения пользователя",
            3: "только просмотр с разрешения пользователя",
            4: "только просмотр без разрешения пользователя",
        }.get(self.shadow_policy, f"значение {self.shadow_policy}")


def read_rdp_config() -> RdpServerConfig:
    cfg = RdpServerConfig()
    if not winapi.IS_WINDOWS:
        cfg.error = "Только Windows"
        return cfg
    import winreg  # pragma: no cover

    def _read(path: str, name: str) -> Optional[int]:  # pragma: no cover
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ) as k:
                value, _ = winreg.QueryValueEx(k, name)
                return int(value)
        except FileNotFoundError:
            return None
        except OSError as e:
            cfg.error = str(e)
            return None

    deny = _read(TS_KEY, "fDenyTSConnections")  # pragma: no cover
    cfg.enabled = None if deny is None else deny == 0
    port = _read(RDP_TCP_KEY, "PortNumber")
    if port:
        cfg.port = port
    pol = _read(TS_POLICY_KEY, "fDenyTSConnections")
    cfg.policy_enabled = None if pol is None else pol == 0
    if cfg.policy_enabled is not None:
        cfg.enabled = cfg.policy_enabled  # групповая политика имеет приоритет
    cfg.shadow_policy = _read(TS_POLICY_KEY, "Shadow")
    return cfg


ConnFunc = Callable[[], list]


def _psutil_connections() -> list:
    import psutil
    return psutil.net_connections(kind="tcp")


class NetworkMonitor:
    def __init__(self, connections_func: Optional[ConnFunc] = None) -> None:
        self._get = connections_func or _psutil_connections
        self._prev: dict[str, NetworkConnection] = {}
        self._initialized = False
        self.status = SourceStatus("tcp", "Таблица TCP-соединений", SourceState.AVAILABLE, "")

    def poll(self, rdp_port: int, now: Optional[datetime] = None) -> tuple[list[NetworkConnection], list[ConnectionEvent]]:
        now = now or datetime.now().astimezone()
        try:
            raw = self._get()
        except Exception as e:  # noqa: BLE001
            state = SourceState.DENIED if e.__class__.__name__ == "AccessDenied" else SourceState.ERROR
            self.status = SourceStatus("tcp", "Таблица TCP-соединений", state,
                                       "Не удалось получить список TCP-соединений", str(e))
            return list(self._prev.values()), []
        conns: dict[str, NetworkConnection] = {}
        for c in raw:
            laddr, raddr = getattr(c, "laddr", None), getattr(c, "raddr", None)
            status = getattr(c, "status", "")
            if not laddr or not raddr or status != "ESTABLISHED":
                continue
            if getattr(laddr, "port", None) != rdp_port:
                continue
            nc = NetworkConnection(laddr.ip, laddr.port, raddr.ip, raddr.port, status, getattr(c, "pid", None))
            conns[nc.key] = nc
        events: list[ConnectionEvent] = []
        for key, nc in conns.items():
            if key not in self._prev:
                note = " (локальный адрес — возможно туннель через другую программу)" if nc.is_loopback else ""
                events.append(ConnectionEvent(
                    timestamp=now, event_type=EventType.NETWORK_CONNECT, source="Таблица TCP",
                    confidence=Confidence.MEDIUM, ip=nc.remote_ip,
                    details=(f"Установлено TCP-соединение {nc.remote_ip}:{nc.remote_port} → порт {nc.local_port} (RDP)"
                             f"{note}. Это сетевое соединение; вход в сеанс подтверждается отдельно."
                             + (" Соединение существовало при запуске монитора." if not self._initialized else "")),
                    key=f"tcp:{key}:{now.timestamp():.0f}",
                    historical=False,
                ))
        for key, nc in self._prev.items():
            if key not in conns:
                events.append(ConnectionEvent(
                    timestamp=now, event_type=EventType.NETWORK_DISCONNECT, source="Таблица TCP",
                    confidence=Confidence.MEDIUM, ip=nc.remote_ip,
                    details=f"TCP-соединение {nc.remote_ip}:{nc.remote_port} → порт {nc.local_port} закрыто.",
                    key=f"tcp-close:{key}:{now.timestamp():.0f}",
                ))
        self._prev = conns
        self._initialized = True
        self.status = SourceStatus("tcp", "Таблица TCP-соединений", SourceState.AVAILABLE,
                                   f"Соединений с RDP-портом {rdp_port}: {len(conns)}")
        return list(conns.values()), events
