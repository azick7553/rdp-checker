"""Локальная история событий в SQLite (%LOCALAPPDATA%\\RDPConnectionMonitor\\history.db)."""
from __future__ import annotations

import csv
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from core.correlation import Upgrade
from core.models import CONFIDENCE_RU, EVENT_TYPE_RU, Confidence, ConnectionEvent, EventType

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    ts_epoch    REAL NOT NULL,
    event_type  TEXT NOT NULL,
    user        TEXT,
    ip          TEXT,
    session_id  INTEGER,
    client_name TEXT,
    source      TEXT,
    confidence  INTEGER NOT NULL,
    details     TEXT,
    ukey        TEXT UNIQUE,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_epoch);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
"""

CONNECTION_TYPES = (
    EventType.RDP_CONNECT.value, EventType.RDP_RECONNECT.value, EventType.RDP_ACTIVE_AT_START.value,
    EventType.SHADOW_START.value,
)


@dataclass
class EventRow:
    id: int
    timestamp: datetime
    event_type: str
    user: str
    ip: str
    session_id: Optional[int]
    client_name: str
    source: str
    confidence: int
    details: str

    @property
    def type_label(self) -> str:
        try:
            return EVENT_TYPE_RU[EventType(self.event_type)]
        except ValueError:
            return self.event_type

    @property
    def confidence_label(self) -> str:
        try:
            return CONFIDENCE_RU[Confidence(self.confidence)]
        except ValueError:
            return str(self.confidence)

    def as_export(self) -> dict:
        return {
            "id": self.id,
            "time": self.timestamp.isoformat(timespec="seconds"),
            "event_type": self.event_type,
            "event": self.type_label,
            "user": self.user,
            "ip": self.ip,
            "session_id": self.session_id,
            "client_name": self.client_name,
            "source": self.source,
            "confidence": self.confidence_label,
            "details": self.details,
        }


class Storage:
    def __init__(self, path: Path | str) -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            try:
                self._conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.DatabaseError:
                pass
            self._conn.executescript(SCHEMA)
            self._conn.commit()
        self._migrate_localized_local_logons()

    def _migrate_localized_local_logons(self) -> None:
        """Исправление записей версии 1.0.0: локальные входы из журналов с адресом «ЛОКАЛЬНЫЕ»
        (русская Windows) ошибочно сохранялись как RDP-подключения."""
        from core.eventlog_monitor import is_remote_address
        with self._lock:
            done = self._conn.execute("SELECT v FROM meta WHERE k = 'migr_local_v2'").fetchone()
            if done:
                return
            rows = self._conn.execute(
                "SELECT id, event_type, ip FROM events WHERE source LIKE 'Журнал %' AND ip IS NOT NULL AND ip != ''"
                " AND event_type IN ('rdp_connect', 'rdp_shell_start', 'rdp_reconnect', 'rdp_disconnect', 'rdp_logoff')"
            ).fetchall()
            fixed = 0
            for r in rows:
                if is_remote_address(r["ip"]):
                    continue
                new_type = {
                    "rdp_connect": "local_logon", "rdp_shell_start": "local_logon",
                    "rdp_logoff": "local_logoff",
                    "rdp_disconnect": "rdp_state_change", "rdp_reconnect": "rdp_state_change",
                }[r["event_type"]]
                self._conn.execute(
                    "UPDATE events SET event_type = ?, confidence = 0, ip = '',"
                    " details = COALESCE(details, '') || ' [Исправлено: локальный вход, адрес «' || ? || '»]'"
                    " WHERE id = ?", (new_type, r["ip"], r["id"]))
                fixed += 1
            self._conn.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('migr_local_v2', ?)", (str(fixed),))
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ write
    def add_event(self, ev: ConnectionEvent) -> bool:
        """Возвращает True, если событие новое (ключ ещё не встречался)."""
        key = ev.key or f"auto:{ev.event_type.value}:{ev.timestamp.timestamp():.3f}:{ev.session_id}:{ev.ip}"
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO events (ts, ts_epoch, event_type, user, ip, session_id, client_name, source,"
                " confidence, details, ukey, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (ev.timestamp.isoformat(), ev.timestamp.timestamp(), ev.event_type.value, ev.user, ev.ip,
                 ev.session_id, ev.client_name, ev.source, int(ev.confidence), ev.details, key,
                 datetime.now().astimezone().isoformat()),
            )
            self._conn.commit()
            if cur.rowcount:
                ev.db_id = cur.lastrowid
                return True
            return False

    def apply_upgrade(self, up: Upgrade) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE events SET confidence = MAX(confidence, ?), details = COALESCE(details,'') || ?"
                " WHERE ukey = ? AND confidence < ?",
                (int(up.confidence), up.note, up.key, int(up.confidence)),
            )
            if up.event_type is not None:
                self._conn.execute("UPDATE events SET event_type = ? WHERE ukey = ?", (up.event_type.value, up.key))
            self._conn.commit()

    def purge(self, retention_days: int) -> int:
        cutoff = (datetime.now().astimezone() - timedelta(days=retention_days)).timestamp()
        with self._lock:
            cur = self._conn.execute("DELETE FROM events WHERE ts_epoch < ?", (cutoff,))
            self._conn.commit()
            return cur.rowcount

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM events")
            self._conn.commit()

    # ------------------------------------------------------------------ read
    @staticmethod
    def _row(r: sqlite3.Row) -> EventRow:
        return EventRow(
            id=r["id"], timestamp=datetime.fromisoformat(r["ts"]), event_type=r["event_type"], user=r["user"] or "",
            ip=r["ip"] or "", session_id=r["session_id"], client_name=r["client_name"] or "", source=r["source"] or "",
            confidence=r["confidence"], details=r["details"] or "",
        )

    def query(self, search: str = "", since: Optional[datetime] = None, until: Optional[datetime] = None,
              types: Optional[list[str]] = None, min_confidence: int = 0, limit: int = 5000) -> list[EventRow]:
        sql = "SELECT * FROM events WHERE confidence >= ?"
        args: list = [min_confidence]
        if since:
            sql += " AND ts_epoch >= ?"
            args.append(since.timestamp())
        if until:
            sql += " AND ts_epoch <= ?"
            args.append(until.timestamp())
        if types:
            sql += f" AND event_type IN ({','.join('?' * len(types))})"
            args.extend(types)
        if search:
            like = f"%{search.lower()}%"
            sql += (" AND (lower(user) LIKE ? OR lower(ip) LIKE ? OR lower(details) LIKE ? OR lower(source) LIKE ?"
                    " OR lower(client_name) LIKE ? OR CAST(session_id AS TEXT) LIKE ?)")
            args.extend([like] * 6)
        sql += " ORDER BY ts_epoch DESC, id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [self._row(r) for r in rows]

    def count_connections_since(self, since: datetime, min_confidence: int = int(Confidence.MEDIUM)) -> int:
        """Число подключений (WTS-подключения и записи журналов, без двойного счёта по ключу)."""
        with self._lock:
            row = self._conn.execute(
                f"SELECT COUNT(*) FROM events WHERE ts_epoch >= ? AND confidence >= ? AND event_type IN "
                f"({','.join('?' * len(CONNECTION_TYPES))}) AND source = 'WTS API'",
                [since.timestamp(), min_confidence, *CONNECTION_TYPES],
            ).fetchone()
            wts = row[0] if row else 0
            row = self._conn.execute(
                f"SELECT COUNT(*) FROM events WHERE ts_epoch >= ? AND confidence >= ? AND event_type IN "
                f"({','.join('?' * len(CONNECTION_TYPES))}) AND source LIKE 'Журнал LSM%'",
                [since.timestamp(), min_confidence, *CONNECTION_TYPES],
            ).fetchone()
            lsm = row[0] if row else 0
        # LSM ведёт полный журнал (включая время, когда монитор не работал); WTS — только пока монитор запущен
        return max(wts, lsm)

    def last_connection(self) -> Optional[EventRow]:
        with self._lock:
            r = self._conn.execute(
                f"SELECT * FROM events WHERE confidence >= ? AND event_type IN ({','.join('?' * len(CONNECTION_TYPES))})"
                " ORDER BY ts_epoch DESC LIMIT 1",
                [int(Confidence.MEDIUM), *CONNECTION_TYPES],
            ).fetchone()
        return self._row(r) if r else None

    def total(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    # ------------------------------------------------------------------ export
    @staticmethod
    def export_csv(rows: list[EventRow], path: str | Path) -> None:
        with open(path, "w", newline="", encoding="utf-8-sig") as f:  # BOM — чтобы Excel понял кириллицу
            fieldnames = list(EventRow.as_export(rows[0]).keys()) if rows else [
                "id", "time", "event_type", "event", "user", "ip", "session_id", "client_name", "source",
                "confidence", "details"]
            w = csv.DictWriter(f, fieldnames=fieldnames, delimiter=";")
            w.writeheader()
            for r in rows:
                w.writerow(r.as_export())

    @staticmethod
    def export_json(rows: list[EventRow], path: str | Path) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump([r.as_export() for r in rows], f, ensure_ascii=False, indent=2)
