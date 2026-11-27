"""Detections on commands from every source (event logs, history, live processes, memory)."""

from __future__ import annotations

from typing import Iterator

from investigation.core.commands import PATTERNS, CommandPattern, collect_commands
from investigation.core.models import Event, Finding
from investigation.core.module import DetectionModule, ErrorSink, ModuleMeta, ModuleType
from investigation.core.registry import register
from investigation.core.requirements import Context
from investigation.core.store import EventStore
from investigation.modules.detections.builtin import load_rules


@register
class CommandRules(DetectionModule):
    meta = ModuleMeta(
        name="command_rules",
        description="Suspicious commands from event logs, PowerShell history, live processes, memory and RunMRU",
        type=ModuleType.DETECTION,
    )

    def detect(self, store: EventStore, ctx: Context, errors: ErrorSink | None = None) -> Iterator[Finding]:
        rows = collect_commands(store)
        try:
            rules = [r for r in load_rules() if r.correlate is None]
        except Exception:
            rules = []

        def reported_elsewhere(event: Event, pattern: CommandPattern) -> bool:
            techniques = {t.split(".")[0] for t in pattern.mitre}
            return any(r.severity >= pattern.severity and techniques & {t.split(".")[0] for t in r.mitre}
                       and r.matches(event) for r in rules)

        for p in PATTERNS:
            hits = [r.event for r in rows if p.id in r.rules and not reported_elsewhere(r.event, p)]
            if hits:
                yield Finding(p.id, p.title, p.severity, p.description, p.mitre, hits)
