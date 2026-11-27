"""timeline.csv (the super-timeline) and commands.csv (every command found) for Timeline Explorer / Excel."""

from __future__ import annotations

import csv
from pathlib import Path

from investigation.core.commands import collect_commands
from investigation.core.module import ModuleMeta, ModuleType, OutputModule
from investigation.core.registry import register
from investigation.core.requirements import Context

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def neutralize(value: object) -> str:
    """Prefix spreadsheet-formula triggers with a quote: log content is attacker-controlled."""
    s = "" if value is None else str(value)
    return "'" + s if s.startswith(FORMULA_PREFIXES) else s


COMMAND_COLUMNS = ["time", "source", "user", "host", "process", "command", "source_file", "suspicious"]
COLUMNS = ["timestamp", "timestamp_desc", "artifact", "evidence_type", "host", "user", "message", "source_file"]


@register
class CsvOutput(OutputModule):
    meta = ModuleMeta(name="csv", description="Super-timeline as timeline.csv and commands as commands.csv", type=ModuleType.OUTPUT)

    def write(self, result, out_dir: Path, ctx: Context) -> list[Path]:
        path = Path(out_dir) / "timeline.csv"
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(COLUMNS)
            for e in result.store.iter_events(include_artefacts=True):
                d = e.to_dict()
                w.writerow([neutralize(d[c]) for c in COLUMNS])
        commands = Path(out_dir) / "commands.csv"
        with commands.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(COMMAND_COLUMNS)
            for r in collect_commands(result.store):
                w.writerow([neutralize(v) for v in (r.time.isoformat() if r.time else "", r.source, r.user, r.host,
                                                    r.process, r.command, r.source_file, " ".join(r.rules))])
        return [path, commands]
