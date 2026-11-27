"""Grouping for the report: findings per (rule, key), identical commands, timeline summary."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

from investigation.core.attack import source_label
from investigation.core.models import Event, Finding

KEY_FIELDS = ("ThreatName", "Threat Name", "ServiceName", "CommandLine", "Image", "NewProcessName", "ImagePath",
              "TargetUserName", "SubjectUserName", "TargetImage", "path", "name", "Name", "rule")
CAP = 100


def _clean(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def key_of(event: Event) -> str:
    """The value that tells one occurrence of a rule from another: threat, service, command, image or user."""
    for name in KEY_FIELDS:
        v = _clean(event.fields.get(name))
        if v and v != "-":
            return v
    return _clean(event.user)


@dataclass
class FindingGroup:
    rule_id: str
    key: str
    findings: list[Finding]
    events: list[Event] = field(default_factory=list)

    @property
    def head(self) -> Finding:
        return self.findings[0]

    @property
    def count(self) -> int:
        return len(self.events)

    @property
    def first(self) -> datetime | None:
        dated = [e.timestamp for e in self.events if "no_timestamp" not in e.tags]
        return min(dated) if dated else None

    @property
    def last(self) -> datetime | None:
        dated = [e.timestamp for e in self.events if "no_timestamp" not in e.tags]
        return max(dated) if dated else None

    @property
    def sources(self) -> list[str]:
        return sorted({source_label(e) for e in self.events})


def group_cards(findings: list[Finding]) -> list[FindingGroup]:
    """One card per (rule id, key value). A finding whose events carry several keys is split by key, so 1230
    Defender events for 17 threats become 17 cards. Order of first appearance is kept; events are de-duplicated
    only by identity of the source event across shadow copies (they are counted, not hidden)."""
    cards: dict[tuple[str, str], FindingGroup] = {}
    for f in findings:
        for e in f.events:
            k = (f.rule_id, key_of(e).casefold())
            card = cards.get(k)
            if card is None:
                card = cards[k] = FindingGroup(f.rule_id, key_of(e), [f])
            elif f not in card.findings:
                card.findings.append(f)
            card.events.append(e)
        if not f.events:
            cards.setdefault((f.rule_id, ""), FindingGroup(f.rule_id, "", [f]))
    return list(cards.values())


@dataclass
class CommandGroup:
    command: str
    rows: list[Any]

    @property
    def count(self) -> int:
        return len(self.rows)


def group_commands(rows: Iterable[Any]) -> list[CommandGroup]:
    """Identical commands (same text, case-sensitive) collapsed into one group, first appearance order."""
    groups: dict[str, CommandGroup] = {}
    for r in rows:
        g = groups.get(r.command)
        if g is None:
            g = groups[r.command] = CommandGroup(r.command, [])
        g.rows.append(r)
    return list(groups.values())


def timeline_summary(day_counts: Iterable[tuple[str, str, int]]) -> list[dict[str, Any]]:
    """[{artifact, days: [(day, n)], total}] from (artifact, day, n) counts, busiest artifact first."""
    per: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for artifact, day, n in day_counts:
        per[artifact].append((day, n))
    out = [{"artifact": a, "days": sorted(d), "total": sum(n for _, n in d)} for a, d in per.items()]
    out.sort(key=lambda x: (-x["total"], x["artifact"]))
    return out
