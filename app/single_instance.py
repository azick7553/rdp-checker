"""Защита от повторного запуска: второй экземпляр просит первый показать окно и завершается."""
from __future__ import annotations

import getpass
import re
import sys

from PySide6.QtCore import QObject, Signal
from PySide6.QtNetwork import QLocalServer, QLocalSocket

from app.config import APP_ID


def _server_name() -> str:
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001
        user = "user"
    return f"{APP_ID}-{re.sub(r'[^A-Za-z0-9_.-]', '_', user)}"


class SingleInstance(QObject):
    activated = Signal(str)   # сообщение от другого экземпляра

    def __init__(self, name: str | None = None, parent=None) -> None:
        super().__init__(parent)
        self.name = name or _server_name()
        self.server: QLocalServer | None = None

    def acquire_mutex(self) -> bool:
        """Windows: именованный мьютекс в пространстве сеанса (Local\\). True — мы первый экземпляр."""
        if sys.platform != "win32":
            return True
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        k32.CreateMutexW.restype = wintypes.HANDLE
        self._mutex = k32.CreateMutexW(None, False, f"Local\\{self.name}")
        return ctypes.get_last_error() != 183  # ERROR_ALREADY_EXISTS

    def notify_existing(self, message: str = "show", timeout_ms: int = 800) -> bool:
        """True — уже работает другой экземпляр (ему отправлено сообщение)."""
        sock = QLocalSocket()
        sock.connectToServer(self.name)
        if not sock.waitForConnected(timeout_ms):
            return False
        sock.write(message.encode("utf-8"))
        sock.flush()
        sock.waitForBytesWritten(timeout_ms)
        sock.disconnectFromServer()
        return True

    def listen(self) -> bool:
        self.server = QLocalServer(self)
        self.server.setSocketOptions(QLocalServer.UserAccessOption)
        if not self.server.listen(self.name):
            # остался «висячий» сокет от аварийно завершённого процесса
            QLocalServer.removeServer(self.name)
            if not self.server.listen(self.name):
                return False
        self.server.newConnection.connect(self._on_connection)
        return True

    def _on_connection(self) -> None:
        while self.server and self.server.hasPendingConnections():
            conn = self.server.nextPendingConnection()
            conn.waitForReadyRead(500)
            msg = bytes(conn.readAll()).decode("utf-8", errors="ignore") or "show"
            conn.disconnectFromServer()
            self.activated.emit(msg)

    def close(self) -> None:
        if self.server:
            self.server.close()
            self.server = None
