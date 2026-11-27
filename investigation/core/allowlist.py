"""Allowlist: events known to be benign are kept out of findings and listed in the report instead."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Iterable

import yaml

from investigation.core.models import Event, Finding
from investigation.core.registry import investigation_home

FILE_NAME = "allowlist.yaml"
EVENT_ATTRIBUTES = ("message", "host", "user", "source_file", "artifact")


@dataclass(frozen=True)
class AllowEntry:
    rule: str
    field: str
    reason: str
    value: str | None = None
    regex: re.Pattern[str] | None = None

    def matches_rule(self, rule_id: str) -> bool:
        return self.rule == "*" or fnmatch.fnmatchcase(rule_id.casefold(), self.rule.casefold())

    def matches_event(self, event: Event) -> bool:
        if self.field in event.fields:
            actual = event.fields[self.field]
        elif self.field in EVENT_ATTRIBUTES:
            actual = getattr(event, self.field)
        else:
            return False
        if actual is None:
            return False
        text = str(actual)
        if self.regex is not None:
            return self.regex.search(text) is not None
        return text.strip().casefold() == str(self.value).strip().casefold()

    @property
    def pattern(self) -> str:
        return f"regex: {self.regex.pattern}" if self.regex is not None else f"value: {self.value}"


@dataclass(frozen=True)
class Suppressed:
    rule_id: str
    title: str
    field: str
    pattern: str
    reason: str
    count: int

    def to_dict(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, "title": self.title, "field": self.field, "pattern": self.pattern,
                "reason": self.reason, "events": self.count}


def parse_entry(raw: Any, origin: str) -> AllowEntry:
    if not isinstance(raw, dict):
        raise ValueError(f"{origin}: entry must be a mapping")
    unknown = set(raw) - {"rule", "field", "value", "regex", "reason"}
    if unknown:
        raise ValueError(f"{origin}: unknown keys: {', '.join(sorted(unknown))}")
    for key in ("rule", "field", "reason"):
        if not str(raw.get(key) or "").strip():
            raise ValueError(f"{origin}: missing {key!r}")
    if ("value" in raw) == ("regex" in raw):
        raise ValueError(f"{origin}: give exactly one of 'value' or 'regex'")
    pattern = None
    if "regex" in raw:
        try:
            pattern = re.compile(str(raw["regex"]), re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"{origin}: bad regex: {exc}") from None
    return AllowEntry(str(raw["rule"]).strip(), str(raw["field"]).strip(), str(raw["reason"]).strip(),
                      None if pattern else str(raw["value"]), pattern)


def allowlist_files(extra: Iterable[str | Path] = ()) -> list[Path]:
    default = investigation_home() / FILE_NAME
    return ([default] if default.is_file() else []) + [Path(p) for p in extra]


def load_allowlist(files: Iterable[Path], errors: Callable[[str, str], None]) -> list[AllowEntry]:
    entries: list[AllowEntry] = []
    for f in files:
        try:
            data = yaml.safe_load(Path(f).read_text(encoding="utf-8-sig")) or []
        except (OSError, yaml.YAMLError) as exc:
            errors("allowlist", f"{f}: cannot read: {exc}")
            continue
        if isinstance(data, dict) and "entries" in data:
            data = data["entries"]
        if not isinstance(data, list):
            errors("allowlist", f"{f}: expected a list of entries")
            continue
        for i, raw in enumerate(data, 1):
            try:
                entries.append(parse_entry(raw, f"{Path(f).name} entry {i}"))
            except ValueError as exc:
                errors("allowlist", f"entry skipped: {exc}")
    return entries


def apply_allowlist(findings: list[Finding], entries: list[AllowEntry]) -> tuple[list[Finding], list[Suppressed]]:
    """Findings without the allowlisted events (a finding left with no events is dropped), and what was suppressed."""
    if not entries:
        return findings, []
    kept: list[Finding] = []
    suppressed: list[Suppressed] = []
    for f in findings:
        mine = [a for a in entries if a.matches_rule(f.rule_id)]
        if not mine:
            kept.append(f)
            continue
        remaining: list[Event] = []
        counts: dict[int, int] = {}
        for e in f.events:
            hit = next((i for i, a in enumerate(mine) if a.matches_event(e)), None)
            if hit is None:
                remaining.append(e)
            else:
                counts[hit] = counts.get(hit, 0) + 1
        for i, n in sorted(counts.items()):
            a = mine[i]
            suppressed.append(Suppressed(f.rule_id, f.title, a.field, a.pattern, a.reason, n))
        if remaining:
            kept.append(replace(f, events=remaining))
    return kept, suppressed
