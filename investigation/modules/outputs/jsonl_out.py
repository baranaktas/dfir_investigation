"""events.jsonl (one event per line) and findings.json (findings + case + preflight)."""

from __future__ import annotations

import json
from pathlib import Path

from investigation.core.module import ModuleMeta, ModuleType, OutputModule
from investigation.core.registry import register
from investigation.core.requirements import Context


@register
class JsonlOutput(OutputModule):
    meta = ModuleMeta(
        name="jsonl", description="events.jsonl and findings.json for SIEM / scripting", type=ModuleType.OUTPUT
    )

    def write(self, result, out_dir: Path, ctx: Context) -> list[Path]:
        out_dir = Path(out_dir)
        events = out_dir / "events.jsonl"
        with events.open("w", encoding="utf-8") as fh:
            for e in result.store.iter_events():
                fh.write(json.dumps(e.to_dict(), ensure_ascii=False) + "\n")
        findings = out_dir / "findings.json"
        findings.write_text(
            json.dumps(
                {
                    "case": result.case,
                    "findings": [f.to_dict() for f in result.sorted_findings()],
                    "preflight": result.preflight.to_dict(),
                    "module_errors": [{"module": m, "message": msg} for m, msg in result.module_errors],
                    "modules_run": result.modules_run,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        stories = out_dir / "stories.json"
        stories.write_text(
            json.dumps({"notes": result.notes, "stories": [s.to_dict() for s in result.stories]},
                       ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return [events, findings, stories]
