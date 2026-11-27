"""One finding per YARA rule that matched, with severity and MITRE from the rule's meta."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterator

from investigation.core.models import Event, Finding, Severity
from investigation.core.module import DetectionModule, ErrorSink, ModuleMeta, ModuleType
from investigation.core.registry import register
from investigation.core.requirements import Context
from investigation.core.store import EventStore


@register
class YaraFindings(DetectionModule):
    meta = ModuleMeta(
        name="yara_findings",
        description="Findings for YARA matches (severity/MITRE from rule meta)",
        type=ModuleType.DETECTION,
        depends_on=("yara",),
    )

    def detect(self, store: EventStore, ctx: Context, errors: ErrorSink | None = None) -> Iterator[Finding]:
        by_rule: dict[str, list[Event]] = defaultdict(list)
        for e in store.iter_events(artifact="yara"):
            by_rule[str(e.fields.get("rule"))].append(e)
        for rule, events in sorted(by_rule.items()):
            first = events[0].fields
            try:
                severity = Severity.parse(first.get("severity") or "high")
            except ValueError:
                severity = Severity.HIGH
            mitre = tuple(m.strip() for m in str(first.get("mitre") or "").split(",") if m.strip())
            yield Finding(
                rule_id=f"YARA-{rule}",
                title=f"YARA match: {rule}",
                severity=severity,
                description=str(first.get("description") or f"Files matched YARA rule {rule}"),
                mitre=mitre,
                events=events[:500],
            )
