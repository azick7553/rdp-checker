"""История подключений: поиск, фильтры, экспорт CSV/JSON."""
from __future__ import annotations

from datetime import datetime, timedelta

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt, QTimer
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox,
    QPushButton, QSplitter, QTableView, QTextBrowser, QVBoxLayout, QWidget,
)

from core.models import EventType
from gui import theme
from gui.widgets import page_header
from services.storage import EventRow, Storage

TYPE_FILTERS = {
    "Все события": None,
    "Подключения": [EventType.RDP_CONNECT, EventType.RDP_RECONNECT, EventType.RDP_ACTIVE_AT_START,
                    EventType.RDP_SHELL_START],
    "Отключения и выход": [EventType.RDP_DISCONNECT, EventType.RDP_LOGOFF, EventType.LOCAL_LOGOFF],
    "RDP-аутентификация (1149)": [EventType.RDP_AUTH],
    "Теневые подключения": [EventType.SHADOW_START, EventType.SHADOW_STOP, EventType.SHADOW_PERMISSION,
                            EventType.SHADOW_SUSPECTED],
    "Сетевые соединения": [EventType.NETWORK_CONNECT, EventType.NETWORK_DISCONNECT],
    "Средства удалённого доступа": [EventType.REMOTE_TOOL_STARTED, EventType.REMOTE_TOOL_STOPPED,
                                    EventType.REMOTE_TOOL_INCOMING],
    "Изменения состояния": [EventType.RDP_STATE_CHANGE, EventType.MISSED_WHILE_AWAY],
}
PERIODS = {"Сегодня": 0, "24 часа": 1, "7 дней": 7, "30 дней": 30, "Вся история": None}
CONF_FILTERS = {"Любая достоверность": 0, "Низкая и выше": 1, "Средняя и выше": 2, "Высокая и выше": 3,
                "Только подтверждённые": 4}
ALERT_TYPES = {"rdp_connect", "rdp_reconnect", "rdp_active_at_start", "shadow_start", "shadow_suspected"}


class HistoryModel(QAbstractTableModel):
    HEADERS = ["Дата и время", "Событие", "Пользователь", "IP-адрес", "Session ID", "Источник", "Достоверность"]

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[EventRow] = []

    def set_rows(self, rows: list[EventRow]) -> None:
        self.beginResetModel()
        self.rows = rows
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
        if not index.isValid():
            return None
        r = self.rows[index.row()]
        c = index.column()
        if role == Qt.DisplayRole:
            return [r.timestamp.strftime("%d.%m.%Y %H:%M:%S"), r.type_label, r.user or "—", r.ip or "—",
                    "" if r.session_id is None else str(r.session_id), r.source, r.confidence_label][c]
        if role == Qt.UserRole:
            return [r.timestamp.timestamp(), r.type_label, r.user, r.ip, -1 if r.session_id is None else r.session_id,
                    r.source, r.confidence][c]
        if role == Qt.ForegroundRole:
            if r.event_type in ALERT_TYPES and r.confidence >= 3 and c in (1, 6):
                return QBrush(QColor(theme.RED))
            if c == 6:
                return QBrush(QColor({0: theme.MUTED, 1: theme.TEXT_2, 2: theme.YELLOW, 3: "#ffb27a",
                                      4: theme.RED}.get(r.confidence, theme.TEXT_2)))
        if role == Qt.ToolTipRole:
            return r.details
        return None


class HistoryView(QWidget):
    def __init__(self, storage: Storage, parent=None) -> None:
        super().__init__(parent)
        self.storage = storage
        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 22, 28, 22)
        lay.setSpacing(12)
        lay.addWidget(page_header("История подключений",
                                  "События из WTS API, журналов Windows, таблицы TCP и журналов программ. "
                                  "Хранится локально на этом компьютере."))
        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Поиск: пользователь, IP, источник, подробности…")
        self.search.setClearButtonEnabled(True)
        self.period = QComboBox()
        self.period.addItems(list(PERIODS))
        self.period.setCurrentText("7 дней")
        self.types = QComboBox()
        self.types.addItems(list(TYPE_FILTERS))
        self.conf = QComboBox()
        self.conf.addItems(list(CONF_FILTERS))
        self.conf.setCurrentText("Низкая и выше")
        bar.addWidget(self.search, 1)
        for w in (self.period, self.types, self.conf):
            bar.addWidget(w)
        lay.addLayout(bar)

        bar2 = QHBoxLayout()
        self.count = QLabel("")
        self.count.setObjectName("Muted")
        bar2.addWidget(self.count, 1)
        b_refresh = QPushButton("Обновить")
        b_csv = QPushButton("Экспорт CSV")
        b_json = QPushButton("Экспорт JSON")
        bar2.addWidget(b_refresh)
        bar2.addWidget(b_csv)
        bar2.addWidget(b_json)
        lay.addLayout(bar2)

        self.model = HistoryModel()
        self.proxy = QSortFilterProxyModel()
        self.proxy.setSourceModel(self.model)
        self.proxy.setSortRole(Qt.UserRole)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.DescendingOrder)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        for i, w in enumerate((145, 200, 150, 115, 75, 175)):
            self.table.setColumnWidth(i, w)
        self.details = QTextBrowser()
        self.details.setPlaceholderText("Выберите событие, чтобы увидеть подробности")
        split = QSplitter(Qt.Vertical)
        split.addWidget(self.table)
        split.addWidget(self.details)
        split.setStretchFactor(0, 4)
        split.setStretchFactor(1, 1)
        lay.addWidget(split, 1)

        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(300)
        self._debounce.timeout.connect(self.reload)
        self.search.textChanged.connect(lambda _=None: self._debounce.start())
        for cb in (self.period, self.types, self.conf):
            cb.currentIndexChanged.connect(self.reload)
        b_refresh.clicked.connect(self.reload)
        b_csv.clicked.connect(lambda: self._export("csv"))
        b_json.clicked.connect(lambda: self._export("json"))
        self.table.selectionModel().selectionChanged.connect(self._on_select)
        self._dirty = True

    def mark_dirty(self) -> None:
        self._dirty = True
        if self.isVisible():
            self.reload()

    def showEvent(self, e):  # noqa: N802
        super().showEvent(e)
        if self._dirty:
            self.reload()

    def _current_rows(self) -> list[EventRow]:
        days = PERIODS[self.period.currentText()]
        now = datetime.now().astimezone()
        since = None
        if days == 0:
            since = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif days:
            since = now - timedelta(days=days)
        types = TYPE_FILTERS[self.types.currentText()]
        return self.storage.query(search=self.search.text().strip(), since=since,
                                  types=[t.value for t in types] if types else None,
                                  min_confidence=CONF_FILTERS[self.conf.currentText()])

    def reload(self) -> None:
        self._dirty = False
        try:
            rows = self._current_rows()
        except Exception as e:  # noqa: BLE001
            self.count.setText(f"Ошибка чтения истории: {e}")
            return
        self.model.set_rows(rows)
        self.count.setText(f"Показано событий: {len(rows)} (всего в базе: {self.storage.total()})")

    def _on_select(self) -> None:
        idx = self.table.selectionModel().selectedRows()
        if not idx:
            return
        r = self.model.rows[self.proxy.mapToSource(idx[0]).row()]
        esc = lambda s: (s or "—").replace("&", "&amp;").replace("<", "&lt;")  # noqa: E731
        self.details.setHtml(
            f"<b>{esc(r.type_label)}</b> — {r.timestamp:%d.%m.%Y %H:%M:%S}<br>"
            f"Пользователь: {esc(r.user)} · IP: {esc(r.ip)} · Сеанс: {r.session_id if r.session_id is not None else '—'}"
            f" · Клиент: {esc(r.client_name)}<br>Источник: {esc(r.source)} · Достоверность: <b>{r.confidence_label}</b>"
            f"<br><br>{esc(r.details)}")

    def _export(self, fmt: str) -> None:
        rows = self.model.rows
        default = f"rdp-history-{datetime.now():%Y%m%d-%H%M}.{fmt}"
        path, _ = QFileDialog.getSaveFileName(self, "Экспорт истории", default,
                                              "CSV (*.csv)" if fmt == "csv" else "JSON (*.json)")
        if not path:
            return
        try:
            (Storage.export_csv if fmt == "csv" else Storage.export_json)(rows, path)
            QMessageBox.information(self, "Экспорт", f"Экспортировано событий: {len(rows)}\n{path}")
        except Exception as e:  # noqa: BLE001
            QMessageBox.warning(self, "Экспорт", f"Не удалось сохранить файл: {e}")
