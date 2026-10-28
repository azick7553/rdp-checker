"""Диагностика возможностей мониторинга на этом компьютере под этой учётной записью."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Optional

from core import winapi
from core.eventlog_monitor import (
    CHANNEL_TITLE, LSM_CHANNEL, RCM_CHANNEL, SECURITY_CHANNEL, EventLogMonitor,
)
from core.models import SOURCE_STATE_RU, SourceState


@dataclass
class DiagnosticItem:
    key: str
    title: str
    state: SourceState
    message: str
    explanation: str = ""

    @property
    def state_label(self) -> str:
        return SOURCE_STATE_RU[self.state]


def _item(key, title, state, message, explanation=""):
    return DiagnosticItem(key, title, state, message, explanation)


def run_diagnostics(detector, notifications_available: Optional[bool] = None,
                    worker_alive: Optional[bool] = None, last_cycle: Optional[datetime] = None) -> list[DiagnosticItem]:
    items: list[DiagnosticItem] = []

    # 1. WTS API
    if not winapi.IS_WINDOWS:
        items.append(_item("wts_api", "WTS API", SourceState.ERROR, "Не Windows",
                           "Приложение предназначено для Windows 10/11."))
    else:
        try:
            winapi.active_console_session_id()
            items.append(_item("wts_api", "WTS API (wtsapi32.dll)", SourceState.AVAILABLE, "Библиотека загружена"))
        except Exception as e:  # noqa: BLE001
            items.append(_item("wts_api", "WTS API (wtsapi32.dll)", SourceState.ERROR, str(e)))

    # 2. Перечисление сеансов
    snap = detector.wts.snapshot()
    st = snap.status
    expl = ""
    if st.state == SourceState.DENIED:
        expl = ("Windows не разрешает этой учётной записи перечислять сеансы (изменены разрешения RDP-Tcp). "
                "Монитор будет опираться на журналы, сетевые соединения и признаки текущего сеанса.")
    elif st.state == SourceState.PARTIAL:
        expl = ("Сеансы видны, но часть сведений о чужих сеансах (имя, IP, время) скрыта. "
                "Факт наличия и состояние сеанса определяются надёжно.")
    others = [s for s in snap.sessions if not s.is_current]
    msg = st.message
    if st.usable:
        msg += f". Других сеансов видно: {len(others)}"
    items.append(_item("wts_enum", "Перечисление сеансов", st.state, msg, expl or st.detail))

    # 3. Текущий сеанс
    if snap.current_session_id is not None:
        own = next((s for s in snap.sessions if s.is_current), None)
        kind = "удалённый (RDP)" if snap.current_is_remote else "локальный (консоль)"
        text = f"Сеанс {snap.current_session_id}, {kind}"
        if own:
            text += f", пользователь {own.full_user or '—'}"
        if snap.current_is_remote_controlled:
            text += ". ВНИМАНИЕ: сеанс сейчас управляется удалённо"
        items.append(_item("current", "Информация о текущем сеансе", SourceState.AVAILABLE, text))
    else:
        items.append(_item("current", "Информация о текущем сеансе", SourceState.ERROR,
                           "Не удалось определить текущий сеанс", "; ".join(snap.errors)))

    # 4–5. Журналы
    probe = EventLogMonitor(lookback_days=1, query_func=getattr(detector.eventlog, "_query", None))
    for ch, key in ((LSM_CHANNEL, "evt_lsm"), (RCM_CHANNEL, "evt_rcm"), (SECURITY_CHANNEL, "evt_security")):
        try:
            probe._query(ch, "*", True, 1)
            items.append(_item(key, CHANNEL_TITLE[ch], SourceState.AVAILABLE, "Чтение разрешено"))
        except Exception as e:  # noqa: BLE001
            state, message = EventLogMonitor.explain_error(ch, e)
            explanation = message
            if ch == SECURITY_CHANNEL and state == SourceState.DENIED:
                explanation += (" Чтение Security Event Log требует прав администратора или членства в группе "
                                "«Читатели журнала событий» (Event Log Readers). Обходить это ограничение приложение не будет.")
            items.append(_item(key, CHANNEL_TITLE[ch], state,
                               "Нет доступа" if state == SourceState.DENIED else "Недоступен", explanation))

    # 6. IP удалённого клиента
    remote = [s for s in snap.sessions if s.is_remote]
    tcp_ok = detector.network.status.usable
    if remote:
        with_ip = [s for s in remote if s.client_ip]
        state = SourceState.AVAILABLE if len(with_ip) == len(remote) else SourceState.PARTIAL
        items.append(_item("client_ip", "Определение IP удалённого клиента", state,
                           f"IP известен для {len(with_ip)} из {len(remote)} RDP-сеансов",
                           "" if state == SourceState.AVAILABLE else
                           "Для части сеансов Windows не отдаёт адрес. Используются также журналы и таблица TCP."))
    elif snap.status.usable:
        items.append(_item("client_ip", "Определение IP удалённого клиента",
                           SourceState.AVAILABLE if tcp_ok else SourceState.PARTIAL,
                           "Будет определён при подключении (WTS API" + (" и таблица TCP)" if tcp_ok else ")"),
                           "Сейчас RDP-сеансов нет, поэтому проверка выполнена косвенно."))
    else:
        items.append(_item("client_ip", "Определение IP удалённого клиента",
                           SourceState.PARTIAL if tcp_ok else SourceState.DENIED,
                           "Только через таблицу TCP-соединений" if tcp_ok else "Нет доступных источников"))

    # 7. Уведомления
    if notifications_available is None:
        items.append(_item("notify", "Системные уведомления", SourceState.PARTIAL, "Не проверено"))
    elif notifications_available:
        items.append(_item("notify", "Системные уведомления", SourceState.AVAILABLE, "Значок в трее и уведомления доступны"))
    else:
        items.append(_item("notify", "Системные уведомления", SourceState.DENIED,
                           "Системный трей или уведомления недоступны",
                           "Уведомления могут быть отключены политикой или режимом «Не беспокоить». "
                           "События всё равно записываются в историю."))

    # 8. Фоновый мониторинг
    if worker_alive is None:
        items.append(_item("worker", "Фоновый мониторинг", SourceState.PARTIAL, "Не запущен"))
    elif worker_alive:
        when = f", последняя проверка {last_cycle:%H:%M:%S}" if last_cycle else ""
        items.append(_item("worker", "Фоновый мониторинг", SourceState.AVAILABLE, "Работает" + when))
    else:
        items.append(_item("worker", "Фоновый мониторинг", SourceState.ERROR, "Остановлен или не отвечает"))

    # Дополнительно
    items.append(_item("tcp", "Таблица TCP-соединений", detector.network.status.state,
                       detector.network.status.message or "Проверяется при опросе", detector.network.status.detail))
    items.append(_item("procs", "Список процессов", detector.tools.status.state,
                       detector.tools.status.message or "Проверяется при опросе",
                       "Процессы других пользователей видны без имени владельца — это нормально."))
    cfg = detector.rdp_config
    if cfg.enabled is None:
        items.append(_item("rdpcfg", "Настройки RDP-сервера (только чтение)", SourceState.PARTIAL,
                           "Не удалось прочитать", cfg.error))
    else:
        text = ("Входящие RDP-подключения РАЗРЕШЕНЫ" if cfg.enabled else "Входящие RDP-подключения запрещены")
        text += f", порт {cfg.port}"
        if snap.listener_present:
            text += ", слушатель RDP-Tcp активен"
        text += f". Политика теневых подключений: {cfg.shadow_description}"
        items.append(_item("rdpcfg", "Настройки RDP-сервера (только чтение)", SourceState.AVAILABLE, text,
                           "Приложение ничего не изменяет в настройках Windows."))
    return items


def diagnostics_report(items: list[DiagnosticItem], extra: Optional[dict] = None) -> str:
    info = winapi.system_info()
    lines = [
        "RDP Connection Monitor — диагностика",
        f"Время: {datetime.now():%d.%m.%Y %H:%M:%S}",
        f"Компьютер: {info['computer']}",
        f"Пользователь: {info['domain']}\\{info['user']}" if info.get("domain") else f"Пользователь: {info['user']}",
        f"ОС: {info['os']} {info['os_version']}",
        "",
    ]
    for it in items:
        lines.append(f"[{it.state_label}] {it.title}: {it.message}")
        if it.explanation:
            lines.append(f"    {it.explanation}")
    if extra:
        lines.append("")
        lines.append(json.dumps(extra, ensure_ascii=False, indent=2, default=str))
    return "\n".join(lines)


def items_to_dict(items: list[DiagnosticItem]) -> list[dict]:
    return [dict(asdict(i), state=i.state.value) for i in items]
