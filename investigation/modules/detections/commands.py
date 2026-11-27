"""Detections on commands from every source (event logs, history, live processes, memory)."""

from __future__ import annotations

from typing import Iterator

from investigation.core.commands import PATTERNS, collect_commands
from investigation.core.models import Finding
from investigation.core.module import DetectionModule, ErrorSink, ModuleMeta, ModuleType
from investigation.core.registry import register
from investigation.core.requirements import Context
from investigation.core.store import EventStore


@register
class CommandRules(DetectionModule):
    meta = ModuleMeta(
        name="command_rules",
        description="Suspicious commands from event logs, PowerShell history, live processes, memory and RunMRU",
        type=ModuleType.DETECTION,
    )

    def detect(self, store: EventStore, ctx: Context, errors: ErrorSink | None = None) -> Iterator[Finding]:
        rows = collect_commands(store)
        for p in PATTERNS:
            hits = [r.event for r in rows if p.id in r.rules and r.source not in p.covered_by_other_rules]
            if hits:
                yield Finding(p.id, p.title, p.severity, p.description, p.mitre, hits)
