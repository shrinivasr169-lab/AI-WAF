"""SQLite audit store.

Rows are only ever written through :func:`EventRecord` builders, so every
value is already redacted. WAL mode is enabled because the Streamlit
dashboard reads the same file from a second process.
"""

from __future__ import annotations

import sqlite3
import statistics
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from logging_store.schemas import EventRecord, row_to_event

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    request_id TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    query TEXT NOT NULL,
    decision TEXT NOT NULL,
    blocked_by TEXT,
    status_code INTEGER NOT NULL,
    rule_ids TEXT NOT NULL DEFAULT '',
    categories TEXT NOT NULL DEFAULT '',
    ml_score REAL,
    ml_flag INTEGER NOT NULL DEFAULT 0,
    latency_ms REAL NOT NULL DEFAULT 0,
    upstream TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_decision ON events(decision);
"""

_INSERT = """
INSERT INTO events (
    timestamp, request_id, client_ip, method, path, query, decision,
    blocked_by, status_code, rule_ids, categories, ml_score, ml_flag,
    latency_ms, upstream, user_agent
) VALUES (
    :timestamp, :request_id, :client_ip, :method, :path, :query, :decision,
    :blocked_by, :status_code, :rule_ids, :categories, :ml_score, :ml_flag,
    :latency_ms, :upstream, :user_agent
)
"""


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_iso() -> str:
    return _iso(datetime.now(timezone.utc))


class EventStore:
    """Thread-safe SQLite wrapper (one connection, guarded by a lock)."""

    def __init__(self, db_path: Path | str, retention_days: int = 30) -> None:
        self.db_path = Path(db_path)
        self.retention_days = retention_days
        # Reentrant: public methods take the lock and then call connect().
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None

    # -- lifecycle ---------------------------------------------------------
    def connect(self) -> sqlite3.Connection:
        with self._lock:
            if self._conn is None:
                self.db_path.parent.mkdir(parents=True, exist_ok=True)
                conn = sqlite3.connect(self.db_path, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA busy_timeout=5000")
                conn.executescript(_SCHEMA)
                conn.commit()
                self._conn = conn
            return self._conn

    @property
    def conn(self) -> sqlite3.Connection:
        return self.connect()

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    # -- writes ------------------------------------------------------------
    def insert(self, event: EventRecord) -> None:
        with self._lock:
            self.connect().execute(_INSERT, event.as_dict())
            self._conn.commit()  # type: ignore[union-attr]

    def insert_many(self, events: Iterable[EventRecord]) -> None:
        rows = [event.as_dict() for event in events]
        if not rows:
            return
        with self._lock:
            self.connect().executemany(_INSERT, rows)
            self._conn.commit()  # type: ignore[union-attr]

    def purge_old(self) -> int:
        """Apply the configured log-retention window."""
        cutoff = _iso(datetime.now(timezone.utc) - timedelta(days=self.retention_days))
        with self._lock:
            cursor = self.connect().execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
            self._conn.commit()  # type: ignore[union-attr]
            return cursor.rowcount

    # -- reads -------------------------------------------------------------
    def query(
        self,
        *,
        decision: str | None = None,
        category: str | None = None,
        search: str | None = None,
        since_minutes: int | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if decision:
            clauses.append("decision = ?")
            params.append(decision)
        if category:
            clauses.append("(categories = ? OR categories LIKE ? OR categories LIKE ? OR categories LIKE ?)")
            params.extend([category, f"{category},%", f"%,{category}", f"%,{category},%"])
        if search:
            clauses.append("(path LIKE ? OR request_id LIKE ? OR client_ip LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like, like])
        if since_minutes is not None:
            cutoff = _iso(datetime.now(timezone.utc) - timedelta(minutes=int(since_minutes)))
            clauses.append("timestamp >= ?")
            params.append(cutoff)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            "SELECT * FROM events "
            f"{where} ORDER BY id DESC LIMIT ? OFFSET ?"
        )
        params.extend([max(1, min(int(limit), 1000)), max(0, int(offset))])
        with self._lock:
            rows = self.connect().execute(sql, params).fetchall()
        return [row_to_event(dict(row)) for row in rows]

    def count(self, *, since_minutes: int | None = None) -> int:
        if since_minutes is None:
            sql, params = "SELECT COUNT(*) FROM events", ()
        else:
            cutoff = _iso(datetime.now(timezone.utc) - timedelta(minutes=int(since_minutes)))
            sql, params = "SELECT COUNT(*) FROM events WHERE timestamp >= ?", (cutoff,)
        with self._lock:
            return int(self.connect().execute(sql, params).fetchone()[0])

    def stats(self, *, since_minutes: int = 60) -> dict[str, Any]:
        """Aggregate metrics for the dashboard (windowed)."""
        cutoff = _iso(datetime.now(timezone.utc) - timedelta(minutes=int(since_minutes)))
        with self._lock:
            rows = self.connect().execute(
                "SELECT timestamp, decision, blocked_by, rule_ids, categories, "
                "ml_score, ml_flag, latency_ms, status_code FROM events "
                "WHERE timestamp >= ? ORDER BY id ASC",
                (cutoff,),
            ).fetchall()

        total = len(rows)
        allowed = blocked = flagged = 0
        by_blocked_by: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        by_bucket: dict[str, dict[str, int]] = {}
        latencies: list[float] = []
        ml_scores: list[float] = []

        for row in rows:
            decision = row["decision"]
            if decision == "block":
                blocked += 1
                blocked_by = row["blocked_by"] or "unknown"
                by_blocked_by[blocked_by] = by_blocked_by.get(blocked_by, 0) + 1
            elif decision == "alert":
                flagged += 1
                allowed += 1
            else:
                allowed += 1

            for category in filter(None, str(row["categories"] or "").split(",")):
                by_category[category] = by_category.get(category, 0) + 1
            for rule_id in filter(None, str(row["rule_ids"] or "").split(",")):
                by_rule[rule_id] = by_rule.get(rule_id, 0) + 1
            if row["ml_score"] is not None:
                ml_scores.append(float(row["ml_score"]))

            bucket = str(row["timestamp"])[:16]  # minute precision
            entry = by_bucket.setdefault(
                bucket, {"bucket": bucket, "total": 0, "allow": 0, "block": 0, "alert": 0}
            )
            entry["total"] += 1
            entry[decision if decision in ("allow", "block", "alert") else "allow"] += 1

            if row["latency_ms"]:
                latencies.append(float(row["latency_ms"]))

        latencies.sort()
        window_seconds = max(since_minutes * 60, 1)
        buckets = [by_bucket[key] for key in sorted(by_bucket)]

        return {
            "window_minutes": since_minutes,
            "total": total,
            "allowed": allowed,
            "blocked": blocked,
            "flagged": flagged,
            "block_rate": round(blocked / total, 4) if total else 0.0,
            "requests_per_second": round(total / window_seconds, 3),
            "latency_ms": _percentiles(latencies),
            "ml_score_avg": round(statistics.fmean(ml_scores), 4) if ml_scores else None,
            "blocked_by": by_blocked_by,
            "categories": dict(sorted(by_category.items(), key=lambda kv: kv[1], reverse=True)),
            "top_rules": dict(sorted(by_rule.items(), key=lambda kv: kv[1], reverse=True)),
            "timeline": buckets,
        }


def _percentiles(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"p50": None, "p95": None, "avg": None, "max": None}
    return {
        "p50": round(statistics.median(values), 2),
        "p95": round(_quantile(values, 0.95), 2),
        "avg": round(statistics.fmean(values), 2),
        "max": round(values[-1], 2),
    }


def _quantile(sorted_values: list[float], q: float) -> float:
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = q * (len(sorted_values) - 1)
    low = int(position)
    high = min(low + 1, len(sorted_values) - 1)
    weight = position - low
    return sorted_values[low] * (1 - weight) + sorted_values[high] * weight
