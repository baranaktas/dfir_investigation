"""timeline.csv - the super-timeline for Timeline Explorer / Excel."""

from __future__ import annotations

import csv
from pathlib import Path

from investigation.core.module import ModuleMeta, ModuleType, OutputModule
from investigation.core.registry import register
from investigation.core.requirements import Context

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def neutralize(value: object) -> str:
    """Prefix spreadsheet-formula triggers with a quote: log content is attacker-controlled."""
    s = "" if value is None else str(value)
    return "'" + s if s.startswith(FORMULA_PREFIXES) else s


COLUMNS = ["timestamp", "timestamp_desc", "artifact", "evidence_type", "host", "user", "message", "source_file"]


@register
class CsvOutput(OutputModule):
    meta = ModuleMeta(name="csv", description="Super-timeline as timeline.csv", type=ModuleType.OUTPUT)

    def write(self, result, out_dir: Path, ctx: Context) -> list[Path]:
        path = Path(out_dir) / "timeline.csv"
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(COLUMNS)
            for e in result.store.iter_events():
                d = e.to_dict()
                w.writerow([neutralize(d[c]) for c in COLUMNS])
        return [path]
