"""Тонкие обёртки ctypes над Windows API.

Используются только документированные функции, доступные обычному пользователю.
Модуль безопасно импортируется на любой ОС: на не-Windows флаг IS_WINDOWS = False,
а функции выбрасывают WinApiUnavailable.
"""
from __future__ import annotations

import ctypes
import os
import platform
import socket
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional

IS_WINDOWS = sys.platform == "win32"

ERROR_ACCESS_DENIED = 5
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NO_MORE_ITEMS = 259
ERROR_EVT_CHANNEL_NOT_FOUND = 15007
ERROR_EVT_INVALID_QUERY = 15001
RPC_S_SERVER_UNAVAILABLE = 1722

CREATE_NO_WINDOW = 0x08000000

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


class WinApiUnavailable(RuntimeError):
    """Windows API недоступен (не Windows или библиотека не загрузилась)."""


class WinApiError(OSError):
    def __init__(self, func: str, code: int):
        self.func = func
        self.code = code
        try:
            msg = ctypes.FormatError(code) if IS_WINDOWS else ""  # type: ignore[attr-defined]
        except Exception:  # pragma: no cover
            msg = ""
        super().__init__(code, f"{func} failed: [{code}] {msg}".strip())

    @property
    def access_denied(self) -> bool:
        return self.code == ERROR_ACCESS_DENIED


def filetime_to_datetime(value: int) -> Optional[datetime]:
    """FILETIME (100-нс интервалы с 1601-01-01 UTC) → локальное aware-время."""
    if not value or value <= 0:
        return None
    try:
        dt = _FILETIME_EPOCH + timedelta(microseconds=value // 10)
        return dt.astimezone()
    except (OverflowError, ValueError, OSError):  # Windows: astimezone() → OSError для дат до 1970
        return None


def parse_client_address(family: int, raw: bytes) -> str:
    """Разбор WTS_CLIENT_ADDRESS.

    AF_INET: IPv4 начинается со смещения 2 (документация Microsoft).
    AF_INET6: 16 байт адреса с начала массива.
    """
    AF_INET, AF_INET6 = 2, 23
    try:
        if family == AF_INET and len(raw) >= 6:
            ip = ".".join(str(b) for b in raw[2:6])
            return "" if ip == "0.0.0.0" else ip
        if family == AF_INET6 and len(raw) >= 16:
            packed = bytes(raw[0:16])
            if not any(packed):
                return ""
            return socket.inet_ntop(socket.AF_INET6, packed)
    except (OSError, ValueError):
        return ""
    return ""


def system_info() -> dict[str, str]:
    info = {
        "computer": os.environ.get("COMPUTERNAME") or platform.node(),
        "user": os.environ.get("USERNAME") or os.environ.get("USER") or "",
        "domain": os.environ.get("USERDOMAIN", ""),
        "os": f"{platform.system()} {platform.release()}",
        "os_version": platform.version(),
        "python": platform.python_version(),
    }
    if IS_WINDOWS:
        try:
            build = sys.getwindowsversion().build  # type: ignore[attr-defined]
            name = "Windows 11" if build >= 22000 else "Windows 10" if build >= 10240 else f"Windows {platform.release()}"
            edition = ""
            try:
                edition = platform.win32_edition() or ""
            except Exception:
                pass
            info["os"] = f"{name} {edition}".strip()
            info["os_version"] = f"сборка {build} ({platform.version()})"
        except Exception:
            pass
    return info


if IS_WINDOWS:  # pragma: no cover - выполняется только на Windows
    from ctypes import wintypes

    _wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _user32 = ctypes.WinDLL("user32", use_last_error=True)

    WTS_CURRENT_SERVER_HANDLE = wintypes.HANDLE(0)
    WTS_CURRENT_SESSION = 0xFFFFFFFF

    class WTS_SESSION_INFOW(ctypes.Structure):
        _fields_ = [
            ("SessionId", wintypes.DWORD),
            ("pWinStationName", wintypes.LPWSTR),
            ("State", ctypes.c_int),
        ]

    class WTS_CLIENT_ADDRESS(ctypes.Structure):
        _fields_ = [("AddressFamily", wintypes.DWORD), ("Address", ctypes.c_ubyte * 20)]

    class WTSINFOW(ctypes.Structure):
        _fields_ = [
            ("State", ctypes.c_int),
            ("SessionId", wintypes.DWORD),
            ("IncomingBytes", wintypes.DWORD),
            ("OutgoingBytes", wintypes.DWORD),
            ("IncomingFrames", wintypes.DWORD),
            ("OutgoingFrames", wintypes.DWORD),
            ("IncomingCompressedBytes", wintypes.DWORD),
            ("OutgoingCompressedBytes", wintypes.DWORD),
            ("WinStationName", wintypes.WCHAR * 32),
            ("Domain", wintypes.WCHAR * 17),
            ("UserName", wintypes.WCHAR * 21),
            ("ConnectTime", ctypes.c_longlong),
            ("DisconnectTime", ctypes.c_longlong),
            ("LastInputTime", ctypes.c_longlong),
            ("LogonTime", ctypes.c_longlong),
            ("CurrentTime", ctypes.c_longlong),
        ]

    _wtsapi32.WTSEnumerateSessionsW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.POINTER(WTS_SESSION_INFOW)), ctypes.POINTER(wintypes.DWORD),
    ]
    _wtsapi32.WTSEnumerateSessionsW.restype = wintypes.BOOL
    _wtsapi32.WTSQuerySessionInformationW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD),
    ]
    _wtsapi32.WTSQuerySessionInformationW.restype = wintypes.BOOL
    _wtsapi32.WTSFreeMemory.argtypes = [ctypes.c_void_p]
    _wtsapi32.WTSFreeMemory.restype = None
    _wtsapi32.WTSRegisterSessionNotification.argtypes = [wintypes.HWND, wintypes.DWORD]
    _wtsapi32.WTSRegisterSessionNotification.restype = wintypes.BOOL
    _wtsapi32.WTSUnRegisterSessionNotification.argtypes = [wintypes.HWND]
    _wtsapi32.WTSUnRegisterSessionNotification.restype = wintypes.BOOL
    _kernel32.WTSGetActiveConsoleSessionId.restype = wintypes.DWORD
    _kernel32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    _kernel32.ProcessIdToSessionId.restype = wintypes.BOOL
    _kernel32.GetCurrentProcessId.restype = wintypes.DWORD
    _user32.GetSystemMetrics.argtypes = [ctypes.c_int]
    _user32.GetSystemMetrics.restype = ctypes.c_int

    # WTS_INFO_CLASS
    WTSWinStationName = 6
    WTSUserName = 5
    WTSDomainName = 7
    WTSConnectState = 8
    WTSClientName = 10
    WTSClientAddress = 14
    WTSClientProtocolType = 16
    WTSSessionInfo = 24

    SM_REMOTESESSION = 0x1000
    SM_REMOTECONTROL = 0x2001

    def wts_enumerate_sessions() -> list[tuple[int, str, int]]:
        p = ctypes.POINTER(WTS_SESSION_INFOW)()
        count = wintypes.DWORD(0)
        if not _wtsapi32.WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, ctypes.byref(p), ctypes.byref(count)):
            raise WinApiError("WTSEnumerateSessionsW", ctypes.get_last_error())
        try:
            return [(p[i].SessionId, p[i].pWinStationName or "", p[i].State) for i in range(count.value)]
        finally:
            _wtsapi32.WTSFreeMemory(p)

    def _wts_query_raw(session_id: int, info_class: int) -> bytes:
        buf = ctypes.c_void_p()
        size = wintypes.DWORD(0)
        if not _wtsapi32.WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE, session_id, info_class, ctypes.byref(buf), ctypes.byref(size)
        ):
            raise WinApiError(f"WTSQuerySessionInformationW({info_class})", ctypes.get_last_error())
        try:
            return ctypes.string_at(buf, size.value) if buf.value else b""
        finally:
            if buf.value:
                _wtsapi32.WTSFreeMemory(buf)

    def wts_query_string(session_id: int, info_class: int) -> str:
        raw = _wts_query_raw(session_id, info_class)
        return raw.decode("utf-16-le", errors="ignore").split("\x00", 1)[0]

    def wts_query_protocol(session_id: int) -> int:
        raw = _wts_query_raw(session_id, WTSClientProtocolType)
        return int.from_bytes(raw[:2], "little") if len(raw) >= 2 else -1

    def wts_query_client_address(session_id: int) -> str:
        raw = _wts_query_raw(session_id, WTSClientAddress)
        if len(raw) < ctypes.sizeof(WTS_CLIENT_ADDRESS):
            return ""
        addr = WTS_CLIENT_ADDRESS.from_buffer_copy(raw)
        return parse_client_address(addr.AddressFamily, bytes(addr.Address))

    def wts_query_session_info(session_id: int) -> dict:
        raw = _wts_query_raw(session_id, WTSSessionInfo)
        if len(raw) < ctypes.sizeof(WTSINFOW):
            return {}
        info = WTSINFOW.from_buffer_copy(raw)
        return {
            "connect_time": filetime_to_datetime(info.ConnectTime),
            "disconnect_time": filetime_to_datetime(info.DisconnectTime),
            "logon_time": filetime_to_datetime(info.LogonTime),
            "user": info.UserName,
            "domain": info.Domain,
            "winstation": info.WinStationName,
        }

    def current_session_id() -> int:
        sid = wintypes.DWORD(0)
        if not _kernel32.ProcessIdToSessionId(_kernel32.GetCurrentProcessId(), ctypes.byref(sid)):
            raise WinApiError("ProcessIdToSessionId", ctypes.get_last_error())
        return int(sid.value)

    def process_session_id(pid: int) -> Optional[int]:
        sid = wintypes.DWORD(0)
        if _kernel32.ProcessIdToSessionId(pid, ctypes.byref(sid)):
            return int(sid.value)
        return None

    def active_console_session_id() -> Optional[int]:
        v = int(_kernel32.WTSGetActiveConsoleSessionId())
        return None if v == 0xFFFFFFFF else v

    def is_remote_session() -> bool:
        return bool(_user32.GetSystemMetrics(SM_REMOTESESSION))

    def is_remote_controlled() -> bool:
        """SM_REMOTECONTROL: текущий сеанс управляется удалённо (Windows 10+)."""
        return bool(_user32.GetSystemMetrics(SM_REMOTECONTROL))

    def register_session_notification(hwnd: int, all_sessions: bool = True) -> bool:
        return bool(_wtsapi32.WTSRegisterSessionNotification(hwnd, 1 if all_sessions else 0))

    def unregister_session_notification(hwnd: int) -> bool:
        return bool(_wtsapi32.WTSUnRegisterSessionNotification(hwnd))

else:
    def _unavailable(*_a, **_k):
        raise WinApiUnavailable("Windows API доступен только в Windows")

    wts_enumerate_sessions = _unavailable
    wts_query_string = _unavailable
    wts_query_protocol = _unavailable
    wts_query_client_address = _unavailable
    wts_query_session_info = _unavailable
    current_session_id = _unavailable
    active_console_session_id = _unavailable
    is_remote_session = _unavailable
    is_remote_controlled = _unavailable
    register_session_notification = _unavailable
    unregister_session_notification = _unavailable

    def process_session_id(pid: int) -> Optional[int]:  # noqa: D401
        return None

    WTSUserName = 5
    WTSDomainName = 7
    WTSClientName = 10
    WTSWinStationName = 6
