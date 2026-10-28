"""Таблица сеансов Windows и TCP-соединений с RDP-портом."""
from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QTableView, QVBoxLayout, QWidget,
)

from core.models import SESSION_STATE_RU, CycleResult, NetworkConnection, Protocol, SessionInfo
from gui import theme
from gui.widgets import SectionTitle, fmt_dt, page_header

PROTO_RU = {Protocol.RDP: "RDP (удалённый)", Protocol.CONSOLE: "Консоль (локальный)", Protocol.ICA: "ICA",
            Protocol.UNKNOWN: "Неизвестно"}


class SessionsModel(QAbstractTableModel):
    HEADERS = ["Пользователь", "IP-адрес", "Session ID", "Состояние", "Время", "Компьютер клиента", "Тип", "Станция"]

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[SessionInfo] = []

    def set_rows(self, rows: list[SessionInfo]) -> None:
        self.beginResetModel()
        self.rows = list(rows)
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):  # noqa: N802
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.HEADERS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        s = self.rows[index.row()]
        col = index.column()
        if role in (Qt.DisplayRole, Qt.UserRole):
            sort = role == Qt.UserRole
            if col == 0:
                u = s.full_user or ("(вход не выполнен)" if s.is_remote else "—")
                return u + (" (вы)" if s.is_current and not sort else "")
            if col == 1:
                return s.client_ip or ("" if sort else ("Недоступен" if s.is_remote else "—"))
            if col == 2:
                return s.session_id
            if col == 3:
                return s.state.value if sort else f"{s.state.value} · {SESSION_STATE_RU.get(s.state, '')}"
            if col == 4:
                t = s.display_time
                return (t.timestamp() if t else 0) if sort else fmt_dt(t)
            if col == 5:
                return s.client_name or ("" if sort else "—")
            if col == 6:
                return PROTO_RU.get(s.protocol, s.protocol.value)
            if col == 7:
                return s.winstation or "—"
        if role == Qt.BackgroundRole and s.is_remote_live:
            return QBrush(QColor(theme.RED_BG))
        if role == Qt.ForegroundRole and s.is_remote_live and col in (0, 1, 3):
            return QBrush(QColor(theme.RED))
        if role == Qt.FontRole and s.is_remote_live:
            f = QFont()
            f.setBold(True)
            return f
        if role == Qt.ToolTipRole:
            tip = [f"Сеанс {s.session_id}", f"Источник: {s.source}"]
            if s.logon_time:
                tip.append(f"Вход: {fmt_dt(s.logon_time)}")
            if s.connect_time:
                tip.append(f"Подключение: {fmt_dt(s.connect_time)}")
            if s.disconnect_time:
                tip.append(f"Отключение: {fmt_dt(s.disconnect_time)}")
            if s.query_errors:
                tip.append("Недоступно: " + "; ".join(s.query_errors))
            return "\n".join(tip)
        return None


class SessionFilter(QSortFilterProxyModel):
    def __init__(self) -> None:
        super().__init__()
        self.mode = 0  # 0 все, 1 только RDP, 2 только активные удалённые
        self.text = ""

    def filterAcceptsRow(self, row, parent):  # noqa: N802
        s: SessionInfo = self.sourceModel().rows[row]
        if self.mode == 1 and not s.is_remote:
            return False
        if self.mode == 2 and not s.is_remote_live:
            return False
        if self.text:
            hay = " ".join([s.full_user, s.client_ip, str(s.session_id), s.state.value, s.client_name, s.winstation]).lower()
            return self.text in hay
        return True


class NetworkModel(QAbstractTableModel):
    HEADERS = ["Удалённый IP", "Удалённый порт", "Локальный порт", "Состояние"]

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[NetworkConnection] = []

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = list(rows)
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):  # noqa: N802
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):  # noqa: N802
        return len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):  # noqa: N802
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.HEADERS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or role != Qt.DisplayRole:
            return None
        c = self.rows[index.row()]
        return [c.remote_ip, c.remote_port, c.local_port, c.status][index.column()]


def _table(model) -> QTableView:
    v = QTableView()
    v.setModel(model)
    v.setAlternatingRowColors(True)
    v.setSelectionBehavior(QAbstractItemView.SelectRows)
    v.setEditTriggers(QAbstractItemView.NoEditTriggers)
    v.verticalHeader().setVisible(False)
    v.horizontalHeader().setStretchLastSection(True)
    v.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
    v.setShowGrid(False)
    v.setWordWrap(False)
    return v


class SessionsView(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 22, 28, 22)
        lay.setSpacing(12)
        lay.addWidget(page_header("Сеансы", "Сеансы Windows на этом компьютере (WTS API). "
                                            "Удалённые RDP-сеансы выделены красным."))
        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Фильтр: пользователь, IP, ID…")
        self.search.setClearButtonEnabled(True)
        self.mode = QComboBox()
        self.mode.addItems(["Все сеансы", "Только RDP", "Только активные удалённые"])
        bar.addWidget(self.search, 1)
        bar.addWidget(self.mode)
        lay.addLayout(bar)

        self.model = SessionsModel()
        self.proxy = SessionFilter()
        self.proxy.setSourceModel(self.model)
        self.proxy.setSortRole(Qt.UserRole)
        self.table = _table(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(2, Qt.AscendingOrder)
        for i, w in enumerate((200, 140, 90, 160, 150, 150, 150)):
            self.table.setColumnWidth(i, w)
        lay.addWidget(self.table, 3)

        self.search.textChanged.connect(self._on_filter)
        self.mode.currentIndexChanged.connect(self._on_filter)

        self.info = QLabel("")
        self.info.setObjectName("Muted")
        self.info.setWordWrap(True)
        lay.addWidget(self.info)

        lay.addWidget(SectionTitle("TCP-соединения с RDP-портом"))
        self.net_hint = QLabel("")
        self.net_hint.setObjectName("Muted")
        self.net_hint.setWordWrap(True)
        lay.addWidget(self.net_hint)
        self.net_model = NetworkModel()
        self.net_table = _table(self.net_model)
        for i, w in enumerate((200, 150, 150)):
            self.net_table.setColumnWidth(i, w)
        lay.addWidget(self.net_table, 1)

    def _on_filter(self) -> None:
        self.proxy.mode = self.mode.currentIndex()
        self.proxy.text = self.search.text().strip().lower()
        self.proxy.invalidate()

    def show_remote_only(self) -> None:
        self.mode.setCurrentIndex(2)

    def update_cycle(self, r: CycleResult) -> None:
        self.model.set_rows(r.sessions)
        wts = r.sources.get("wts")
        parts = []
        if wts:
            parts.append(f"Источник: {wts.title} — {wts.message}")
        if r.current_session_id is not None:
            parts.append(f"Ваш сеанс: {r.current_session_id}" + (" (удалённый)" if r.current_session_remote else ""))
        if r.rdp_server_enabled is not None:
            parts.append("RDP-сервер: " + ("включён" if r.rdp_server_enabled else "выключен") + f", порт {r.rdp_port}")
        self.info.setText(" · ".join(parts))
        self.net_model.set_rows(r.network)
        tcp = r.sources.get("tcp")
        self.net_hint.setText(
            (f"Установленные соединения с локальным портом {r.rdp_port}. "
             "Соединение показывает адрес удалённого компьютера даже до входа в сеанс. ")
            + (f"[{tcp.message}]" if tcp else ""))
