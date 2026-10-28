"""Вкладка «Настройки»."""
from __future__ import annotations

import os
import subprocess
import sys

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton,
    QScrollArea, QSpinBox, QVBoxLayout, QWidget,
)

from app.config import NOTIFY_CATEGORIES, SOUND_CHOICES, Settings, data_dir
from gui.widgets import Card, SectionTitle, page_header


class SettingsView(QScrollArea):
    settings_changed = Signal(object)        # Settings
    test_notification = Signal()
    test_sound = Signal()
    clear_history = Signal()

    def __init__(self, settings: Settings, parent=None) -> None:
        super().__init__(parent)
        self.settings = settings
        self.setWidgetResizable(True)
        body = QWidget()
        self.setWidget(body)
        lay = QVBoxLayout(body)
        lay.setContentsMargins(28, 22, 28, 22)
        lay.setSpacing(12)
        lay.addWidget(page_header("Настройки", "Изменения применяются сразу после сохранения."))

        # --- мониторинг
        c = Card()
        c.lay.addWidget(SectionTitle("Мониторинг"))
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignLeft)
        form.setHorizontalSpacing(18)
        self.interval = QSpinBox()
        self.interval.setRange(1, 30)
        self.interval.setSuffix(" с")
        form.addRow("Интервал проверки", self.interval)
        self.lookback = QSpinBox()
        self.lookback.setRange(1, 90)
        self.lookback.setSuffix(" дн.")
        form.addRow("Загружать события журналов за", self.lookback)
        self.retention = QSpinBox()
        self.retention.setRange(1, 3650)
        self.retention.setSuffix(" дн.")
        form.addRow("Хранить историю", self.retention)
        for w in (self.interval, self.lookback, self.retention):
            w.setMaximumWidth(160)
        c.lay.addLayout(form)
        self.read_security = QCheckBox("Пытаться читать журнал Security (обычно требуются права администратора)")
        self.remote_tools = QCheckBox("Проверять другие средства удалённого доступа")
        c.lay.addWidget(self.read_security)
        c.lay.addWidget(self.remote_tools)
        hint = QLabel("Интервал и срок хранения применяются сразу; источники данных и глубина загрузки "
                      "журналов — после перезапуска приложения.")
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        c.lay.addWidget(hint)
        lay.addWidget(c)

        # --- окно
        c = Card()
        c.lay.addWidget(SectionTitle("Окно и трей"))
        self.to_tray = QCheckBox("При закрытии окна сворачивать в системный трей")
        self.start_min = QCheckBox("Запускать свёрнутым в трей")
        c.lay.addWidget(self.to_tray)
        c.lay.addWidget(self.start_min)
        lay.addWidget(c)

        # --- уведомления
        c = Card()
        c.lay.addWidget(SectionTitle("Уведомления"))
        self.notify_on = QCheckBox("Показывать системные уведомления")
        c.lay.addWidget(self.notify_on)
        self.cat_boxes: dict[str, QCheckBox] = {}
        for key, title in NOTIFY_CATEGORIES.items():
            cb = QCheckBox(title)
            cb.setStyleSheet("margin-left: 22px;")
            self.cat_boxes[key] = cb
            c.lay.addWidget(cb)
        self.notify_on.toggled.connect(lambda on: [b.setEnabled(on) for b in self.cat_boxes.values()])
        form = QFormLayout()
        self.sound = QComboBox()
        self.sound.setMaximumWidth(260)
        for k, v in SOUND_CHOICES.items():
            self.sound.addItem(v, k)
        form.addRow("Звук", self.sound)
        h = QHBoxLayout()
        self.sound_path = QLineEdit()
        self.sound_path.setPlaceholderText("Путь к WAV-файлу")
        b_browse = QPushButton("Обзор…")
        b_browse.clicked.connect(self._browse)
        h.addWidget(self.sound_path, 1)
        h.addWidget(b_browse)
        form.addRow("Свой звук", h)
        c.lay.addLayout(form)
        self.sound_disc = QCheckBox("Звук также при отключении и завершении сеанса")
        c.lay.addWidget(self.sound_disc)
        h = QHBoxLayout()
        b_tn = QPushButton("Тестовое уведомление")
        b_ts = QPushButton("Проверить звук")
        b_tn.clicked.connect(self.test_notification)
        b_ts.clicked.connect(self._test_sound)
        h.addWidget(b_tn)
        h.addWidget(b_ts)
        h.addStretch(1)
        c.lay.addLayout(h)
        lay.addWidget(c)

        # --- данные
        c = Card()
        c.lay.addWidget(SectionTitle("Данные"))
        p = QLabel(f"Папка данных: {data_dir()}")
        p.setObjectName("Muted")
        p.setTextInteractionFlags(Qt.TextSelectableByMouse)
        p.setWordWrap(True)
        c.lay.addWidget(p)
        h = QHBoxLayout()
        b_open = QPushButton("Открыть папку")
        b_open.clicked.connect(self._open_folder)
        b_clear = QPushButton("Очистить историю")
        b_clear.setObjectName("Danger")
        b_clear.clicked.connect(self._confirm_clear)
        h.addWidget(b_open)
        h.addWidget(b_clear)
        h.addStretch(1)
        c.lay.addLayout(h)
        lay.addWidget(c)

        h = QHBoxLayout()
        self.saved = QLabel("")
        self.saved.setObjectName("Muted")
        b_save = QPushButton("Сохранить")
        b_save.setObjectName("Primary")
        b_reset = QPushButton("Отменить изменения")
        b_save.clicked.connect(self._save)
        b_reset.clicked.connect(self.load)
        h.addStretch(1)
        h.addWidget(self.saved)
        h.addWidget(b_reset)
        h.addWidget(b_save)
        lay.addLayout(h)
        lay.addStretch(1)
        self.load()

    def load(self) -> None:
        s = self.settings
        self.interval.setValue(s.poll_interval)
        self.lookback.setValue(s.eventlog_lookback_days)
        self.retention.setValue(s.retention_days)
        self.read_security.setChecked(s.read_security_log)
        self.remote_tools.setChecked(s.remote_tools_enabled)
        self.to_tray.setChecked(s.minimize_to_tray)
        self.start_min.setChecked(s.start_minimized)
        self.notify_on.setChecked(s.notifications_enabled)
        for k, cb in self.cat_boxes.items():
            cb.setChecked(bool(s.notify.get(k, True)))
            cb.setEnabled(s.notifications_enabled)
        self.sound.setCurrentIndex(max(0, self.sound.findData(s.sound)))
        self.sound_path.setText(s.custom_sound_path)
        self.sound_disc.setChecked(s.sound_on_disconnect)
        self.saved.setText("")

    def _collect(self) -> None:
        s = self.settings
        s.poll_interval = self.interval.value()
        s.eventlog_lookback_days = self.lookback.value()
        s.retention_days = self.retention.value()
        s.read_security_log = self.read_security.isChecked()
        s.remote_tools_enabled = self.remote_tools.isChecked()
        s.minimize_to_tray = self.to_tray.isChecked()
        s.start_minimized = self.start_min.isChecked()
        s.notifications_enabled = self.notify_on.isChecked()
        s.notify = {k: cb.isChecked() for k, cb in self.cat_boxes.items()}
        s.sound = self.sound.currentData()
        s.custom_sound_path = self.sound_path.text().strip()
        s.sound_on_disconnect = self.sound_disc.isChecked()
        s.validate()

    def _save(self) -> None:
        self._collect()
        try:
            self.settings.save()
            self.saved.setText("Сохранено")
        except OSError as e:
            self.saved.setText(f"Не удалось сохранить: {e}")
        self.settings_changed.emit(self.settings)

    def _test_sound(self) -> None:
        self._collect()
        self.test_sound.emit()

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Выберите звук", "", "WAV (*.wav)")
        if path:
            self.sound_path.setText(path)
            self.sound.setCurrentIndex(self.sound.findData("custom"))

    def _open_folder(self) -> None:
        path = str(data_dir())
        try:
            if sys.platform == "win32":
                os.startfile(path)  # type: ignore[attr-defined]
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception:  # noqa: BLE001
            pass

    def _confirm_clear(self) -> None:
        if QMessageBox.question(self, "Очистить историю", "Удалить все сохранённые события?") == QMessageBox.Yes:
            self.clear_history.emit()
