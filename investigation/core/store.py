"""SQLite-backed event store (the super-timeline)."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from itertools import islice
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from investigation.core.models import Event, EvidenceType, json_safe

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    timestamp_desc TEXT,
    artifact TEXT,
    source_file TEXT,
    host TEXT,
    user TEXT,
    message TEXT,
    evidence_type TEXT,
    fields TEXT,
    tags TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_artifact ON events(artifact);
CREATE INDEX IF NOT EXISTS idx_events_et ON events(evidence_type, timestamp);
"""


def _ts_key(ts: datetime) -> str:
    from datetime import timezone

    return ts.astimezone(timezone.utc).isoformat()


_ORDER = " ORDER BY CASE WHEN tags LIKE '%\"no_timestamp\"%' THEN 1 ELSE 0 END, timestamp, id"
_COLUMNS = ("SELECT timestamp, timestamp_desc, artifact, source_file, host, user, message, evidence_type,"
            " fields, tags FROM events")


def _like(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class EventStore:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self._db: sqlite3.Connection | None = sqlite3.connect(str(self.db_path))
        self._db.executescript(_SCHEMA)

    @property
    def _conn(self) -> sqlite3.Connection:
        """Reopened on demand after close(): Windows cannot delete or overwrite an open database file."""
        if self._db is None:
            self._db = sqlite3.connect(str(self.db_path))
        return self._db

    def add_many(self, events: Iterable[Event]) -> int:
        total = 0
        it = iter(events)
        while True:
            batch = list(islice(it, 1000))
            if not batch:
                break
            rows = []
            for e in batch:
                d = e.to_dict()
                rows.append((
                    _ts_key(e.timestamp), d["timestamp_desc"], d["artifact"], d["source_file"], d["host"],
                    d["user"], d["message"], d["evidence_type"],
                    json.dumps(d["fields"], ensure_ascii=False), json.dumps(d["tags"], ensure_ascii=False),
                ))
            self._conn.executemany(
                "INSERT INTO events (timestamp, timestamp_desc, artifact, source_file, host, user, message,"
                " evidence_type, fields, tags) VALUES (?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
            self._conn.commit()
            total += len(rows)
        return total

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def iter_events(
        self,
        artifact: str | None = None,
        field_equals: Mapping[str, Any] | None = None,
        limit: int | None = None,
    ) -> Iterator[Event]:
        where, params = [], []
        if artifact is not None:
            where.append("artifact = ?")
            params.append(artifact)
        for k, v in (field_equals or {}).items():
            where.append("json_extract(fields, ?) = ?")
            params.extend([f'$."{k}"', json_safe(v)])
        sql = _COLUMNS
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += _ORDER
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        for row in self._conn.execute(sql, params):
            yield self._row(row)

    def iter_with_id(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        evidence_type: str | None = None,
        limit: int | None = None,
    ) -> Iterator[tuple[int, Event]]:
        """Stream (row id, event) ordered by (timestamp, id) so an index serves the sort (no temp B-tree).
        With a time range, undated (no_timestamp) records are left out. With an evidence type, dated records
        come first and undated ones (1970 placeholder) follow in a separate bounded pass at the end."""
        base = "SELECT id, " + _COLUMNS[len("SELECT "):]
        undated = "tags LIKE '%\"no_timestamp\"%'"
        where, params = [], []
        if start is not None and end is not None:
            where.append("timestamp BETWEEN ? AND ?")
            params += [_ts_key(start), _ts_key(end)]
        if evidence_type is not None:
            where.append("evidence_type = ?")
            params.append(evidence_type)
        passes = [f"NOT ({undated})"]
        if start is not None and end is not None:
            pass
        elif evidence_type is not None:
            passes.append(f"({undated}) AND timestamp < '1971'")
        else:
            passes = [None]
        left = limit
        for extra in passes:
            conds = where + ([extra] if extra else [])
            sql = base + (" WHERE " + " AND ".join(conds) if conds else "") + " ORDER BY timestamp, id"
            if left is not None:
                if left <= 0:
                    return
                sql += f" LIMIT {int(left)}"
            n = 0
            for row in self._conn.execute(sql, params):
                n += 1
                yield row[0], self._row(row[1:])
            if left is not None:
                left -= n

    def evidence_counts(self) -> dict[str, int]:
        return dict(self._conn.execute(
            "SELECT COALESCE(evidence_type, 'other'), COUNT(*) FROM events GROUP BY 1 ORDER BY 1"))

    def source_counts(self) -> dict[str, int]:
        """Events per source kind (live/disk/vss/memory), same rules as attack.source_label, computed in SQL."""
        out = {"live": 0, "disk": 0, "vss": 0, "memory": 0}
        for artifact, vss, n in self._conn.execute(
            "SELECT artifact, source_file GLOB 'vss:[0-9]*:*', COUNT(*) FROM events GROUP BY 1, 2"
        ):
            a = artifact or ""
            kind = "vss" if vss else "live" if a.startswith("live_") else "memory" if a.startswith("memory_") else "disk"
            out[kind] += n
        return out

    @staticmethod
    def _row(row) -> Event:
        return Event(
                timestamp=datetime.fromisoformat(row[0]),
                timestamp_desc=row[1],
                artifact=row[2],
                source_file=row[3],
                host=row[4],
                user=row[5],
                message=row[6],
                evidence_type=EvidenceType(row[7] or "other"),
                fields=json.loads(row[8]) if row[8] else {},
                tags=tuple(json.loads(row[9])) if row[9] else (),
        )

    def search(self, text: str, limit: int = 200) -> list[Event]:
        """Events whose message or any field contains `text`, time-ordered. Case-insensitive for ASCII
        (SQLite LIKE); for non-ASCII names every case variant seen is tried."""
        variants = list(dict.fromkeys([text, text.lower(), text.upper(), text.casefold(), text.title()]))
        where = " OR ".join(["message LIKE ? ESCAPE '\\' OR fields LIKE ? ESCAPE '\\'"] * len(variants))
        params: list[str] = []
        for v in variants:
            params += [_like(v), _like(json.dumps(v)[1:-1])]
        sql = f"{_COLUMNS} WHERE {where}{_ORDER} LIMIT {int(limit)}"
        return [self._row(r) for r in self._conn.execute(sql, params)]

    def artifact_counts(self) -> dict[str, int]:
        return dict(self._conn.execute("SELECT artifact, COUNT(*) FROM events GROUP BY artifact ORDER BY artifact"))

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None
