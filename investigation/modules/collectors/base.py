"""CSV writing/reading shared by collectors (write side) and the analysis side (read side)."""

from __future__ import annotations

import csv
import dataclasses
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar, Iterable, Iterator, Mapping, Sequence

from investigation.core.module import CollectorModule
from investigation.core.requirements import Context

_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        text = value.astimezone(timezone.utc).isoformat()
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, (list, tuple, set, frozenset)):
        text = "; ".join(_cell(v) for v in value)
    else:
        text = str(value)
    return "'" + text if text.startswith(_TRIGGERS) else text


def write_csv(path: Path, columns: Sequence[str], rows: Iterable[Mapping[str, Any]]) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(path, "w", encoding="utf-8-sig", errors="backslashreplace", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(columns)
        for row in rows:
            writer.writerow([_cell(row.get(c)) for c in columns])
            n += 1
    return n


def read_csv(path: Path) -> Iterator[dict[str, str]]:
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            yield {
                k: v[1:] if isinstance(v, str) and v.startswith("'") and v[1:2] in _TRIGGERS and v[1:2] != "" else v
                for k, v in row.items()
            }


class VolatileCollector(CollectorModule):
    """A collector that writes one CSV under volatile/. Subclasses set filename/columns and rows()."""

    filename: ClassVar[str]
    columns: ClassVar[tuple[str, ...]]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        meta = cls.__dict__.get("meta")
        if meta is not None and not meta.category:
            cls.meta = dataclasses.replace(meta, category="live")

    def rows(self, ctx: Context) -> Iterable[Mapping[str, Any]]:
        raise NotImplementedError

    def collect(self, ctx: Context, out_dir: Path) -> int:
        return write_csv(Path(out_dir) / "volatile" / self.filename, self.columns, self.rows(ctx))
