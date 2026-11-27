"""Built-in YAML rule engine with threshold / distinct / sequence correlation.

Rules live in investigation/rules/builtin/*.yaml and $INVESTIGATION_HOME/rules/*.yaml.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

import yaml

from investigation.core.models import Event, Finding, Severity
from investigation.core.module import DetectionModule, ErrorSink, ModuleMeta, ModuleType
from investigation.core.registry import investigation_home, register
from investigation.core.requirements import Context
from investigation.core.store import EventStore
from investigation.core.frozen import resource

BUILTIN_RULES_DIR = resource("rules/builtin")

RULE_KEYS = {
    "id", "title", "severity", "mitre", "description", "note", "artifact", "match", "contains",
    "contains_all", "endswith", "not", "not_endswith", "not_contains", "regex", "not_regex", "not_all_regex", "correlate",
    "process_creation",
}
CORRELATE_KEYS = {
    "threshold": {"type", "count", "window_seconds", "group_by"},
    "distinct": {"type", "field", "count", "window_seconds", "group_by"},
    "sequence": {"type", "then", "min_count", "window_seconds", "group_by"},
}

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
PROC_4688_RENAME = {"Image": "NewProcessName", "ParentImage": "ParentProcessName"}


def _norm(v: Any) -> str:
    return str(v).strip().casefold()


def _values(event: Event, key: str) -> list[Any]:
    """Values of `key`; 'a|b|c' means any of these fields (missing ones are skipped)."""
    return [v for k in key.split("|") if (v := _get(event, k)) is not None]


def _get(event: Event, key: str) -> Any:
    if key in event.fields:
        return event.fields[key]
    if key in ("message", "host", "user", "source_file", "artifact"):
        return getattr(event, key)
    return None


def _as_list(v: Any) -> list[Any]:
    return list(v) if isinstance(v, (list, tuple)) else [v]


def _match_eq(event: Event, cond: Mapping[str, Any]) -> bool:
    for k, expected in cond.items():
        wanted = [_norm(x) for x in _as_list(expected)]
        if not any(_norm(a) in wanted for a in _values(event, k)):
            return False
    return True


def _match_contains(event: Event, cond: Mapping[str, Any]) -> bool:
    for k, needles in cond.items():
        ns = [str(n).casefold() for n in _as_list(needles)]
        if not any(n in str(a).casefold() for a in _values(event, k) for n in ns):
            return False
    return True


def _compile(cond: Mapping[str, Any], origin: str) -> dict[str, list[re.Pattern[str]]]:
    out: dict[str, list[re.Pattern[str]]] = {}
    for k, patterns in cond.items():
        try:
            out[k] = [re.compile(str(p), re.IGNORECASE | re.ASCII) for p in _as_list(patterns)]
        except re.error as exc:
            raise ValueError(f"{origin}: bad regex for {k!r}: {exc}") from None
    return out


def _match_regex(event: Event, cond: Mapping[str, list[re.Pattern[str]]]) -> bool:
    """Every key: some field value matches some pattern (re.search; anchor with ^/$ yourself)."""
    return all(any(p.search(str(v)) for v in _values(event, k) for p in pats) for k, pats in cond.items())


def _match_regex_any(event: Event, cond: Mapping[str, list[re.Pattern[str]]]) -> bool:
    return any(_match_regex(event, {k: v}) for k, v in cond.items())


def _match_contains_any(event: Event, cond: Mapping[str, Any]) -> bool:
    """True if ANY listed field contains any needle (used for exclusions)."""
    return any(_match_contains(event, {k: v}) for k, v in cond.items())


def _match_endswith(event: Event, cond: Mapping[str, Any]) -> bool:
    for k, suffixes in cond.items():
        ss = [_norm(s) for s in _as_list(suffixes)]
        if not any(_norm(a).endswith(s) for a in _values(event, k) for s in ss):
            return False
    return True


def _match_contains_all(event: Event, cond: Mapping[str, Any]) -> bool:
    for k, groups in cond.items():
        if not all(_match_contains(event, {k: g}) for g in groups):
            return False
    return True


@dataclass
class Rule:
    id: str
    title: str
    severity: Severity
    mitre: tuple[str, ...]
    description: str
    artifact: str | tuple[str, ...] = "evtx"
    note: str | None = None
    match: dict[str, Any] = field(default_factory=dict)
    contains: dict[str, Any] = field(default_factory=dict)
    contains_all: dict[str, Any] = field(default_factory=dict)
    endswith: dict[str, Any] = field(default_factory=dict)
    not_: dict[str, Any] = field(default_factory=dict)
    not_endswith: dict[str, Any] = field(default_factory=dict)
    not_contains: dict[str, Any] = field(default_factory=dict)
    regex: dict[str, Any] = field(default_factory=dict)
    not_regex: dict[str, Any] = field(default_factory=dict)
    not_all_regex: dict[str, Any] = field(default_factory=dict)
    correlate: dict[str, Any] | None = None

    @property
    def artifacts(self) -> tuple[str, ...]:
        return self.artifact if isinstance(self.artifact, tuple) else (self.artifact,)

    def matches(self, event: Event) -> bool:
        if event.artifact not in self.artifacts:
            return False
        if self.match and not _match_eq(event, self.match):
            return False
        if self.contains and not _match_contains(event, self.contains):
            return False
        if self.contains_all and not _match_contains_all(event, self.contains_all):
            return False
        if self.endswith and not _match_endswith(event, self.endswith):
            return False
        if self.not_ and _match_eq(event, self.not_):
            return False
        if self.not_endswith and _match_endswith(event, self.not_endswith):
            return False
        if self.not_contains and _match_contains_any(event, self.not_contains):
            return False
        if self.regex and not _match_regex(event, self.regex):
            return False
        if self.not_regex and _match_regex_any(event, self.not_regex):
            return False
        if self.not_all_regex and _match_regex(event, self.not_all_regex):
            return False
        return True

    def finding(self, events: list[Event]) -> Finding:
        return Finding(self.id, self.title, self.severity, self.description, self.mitre, events, self.note)


def _rename(d: Mapping[str, Any], mapping: Mapping[str, str]) -> dict[str, Any]:
    return {mapping.get(k, k): v for k, v in d.items()}


def _parse_rule(raw: Any, origin: str) -> list[Rule]:
    if not isinstance(raw, dict):
        raise ValueError(f"{origin}: rule must be a mapping")
    unknown = set(raw) - RULE_KEYS
    if unknown:
        raise ValueError(f"{origin}: rule {raw.get('id')!r} has unknown keys: {', '.join(sorted(unknown))}")
    for req in ("id", "title", "severity", "mitre", "description"):
        if req not in raw:
            raise ValueError(f"{origin}: rule {raw.get('id')!r} missing {req!r}")
    corr = raw.get("correlate")
    if corr is not None:
        ctype = corr.get("type") if isinstance(corr, dict) else None
        if ctype not in CORRELATE_KEYS:
            raise ValueError(f"{origin}: rule {raw['id']!r} has invalid correlate type {ctype!r}")
        bad = set(corr) - CORRELATE_KEYS[ctype]
        missing = CORRELATE_KEYS[ctype] - set(corr)
        if bad or missing:
            raise ValueError(f"{origin}: rule {raw['id']!r} correlate keys wrong (extra={bad}, missing={missing})")
    base = Rule(
        id=str(raw["id"]),
        title=str(raw["title"]),
        severity=Severity.parse(raw["severity"]),
        mitre=tuple(str(m) for m in _as_list(raw["mitre"])),
        description=str(raw["description"]).strip(),
        artifact=(tuple(str(a) for a in raw["artifact"]) if isinstance(raw.get("artifact"), list)
                  else str(raw.get("artifact", "evtx"))),
        note=raw.get("note"),
        match=dict(raw.get("match") or {}),
        contains=dict(raw.get("contains") or {}),
        contains_all=dict(raw.get("contains_all") or {}),
        endswith=dict(raw.get("endswith") or {}),
        not_=dict(raw.get("not") or {}),
        not_endswith=dict(raw.get("not_endswith") or {}),
        not_contains=dict(raw.get("not_contains") or {}),
        regex=_compile(raw.get("regex") or {}, origin),
        not_regex=_compile(raw.get("not_regex") or {}, origin),
        not_all_regex=_compile(raw.get("not_all_regex") or {}, origin),
        correlate=dict(corr) if corr else None,
    )
    if not raw.get("process_creation"):
        return [base]
    sysmon = replace(base, id=f"{base.id}a", match={"EventID": 1, "Channel": SYSMON_CHANNEL, **base.match})
    r = lambda d: _rename(d, PROC_4688_RENAME)
    security = replace(
        base, id=f"{base.id}b", match={"EventID": 4688, **r(base.match)}, contains=r(base.contains),
        contains_all=r(base.contains_all), endswith=r(base.endswith), not_=r(base.not_),
        not_endswith=r(base.not_endswith), not_contains=r(base.not_contains), regex=r(base.regex),
        not_regex=r(base.not_regex), not_all_regex=r(base.not_all_regex),
    )
    return [sysmon, security]


def rule_files() -> list[Path]:
    files = sorted(BUILTIN_RULES_DIR.glob("*.y*ml"))
    user = investigation_home() / "rules"
    if user.is_dir():
        files += sorted(user.glob("*.y*ml"))
    return files


def _load_file(f: Path, seen: set[str]) -> list[Rule]:
    data = yaml.safe_load(f.read_text(encoding="utf-8")) or []
    if not isinstance(data, list):
        raise ValueError(f"{f}: expected a list of rules")
    rules: list[Rule] = []
    ids: set[str] = set()
    for raw in data:
        for rule in _parse_rule(raw, str(f)):
            if rule.id in seen or rule.id in ids:
                raise ValueError(f"{f}: duplicate rule id {rule.id!r}")
            ids.add(rule.id)
            rules.append(rule)
    return rules


def load_rules(files: Iterable[Path] | None = None, errors: ErrorSink | None = None) -> list[Rule]:
    """Load all rule files. Without `errors` any bad file raises; with it, a bad file is reported
    and skipped as a whole while every other file still loads."""
    rules: list[Rule] = []
    seen: set[str] = set()
    for f in files if files is not None else rule_files():
        try:
            loaded = _load_file(f, seen)
        except (ValueError, OSError, yaml.YAMLError) as exc:
            if errors is None:
                raise
            errors("builtin_rules", f"rule file {f.name} skipped: {exc}")
            continue
        seen.update(r.id for r in loaded)
        rules.extend(loaded)
    return rules


def _group_key(event: Event, field_name: str) -> str | None:
    v = _get(event, field_name)
    if v is None:
        return None
    s = str(v).strip()
    if s in ("", "-"):
        return None
    return s.casefold()


def _grouped(events: list[Event], group_by: str) -> dict[str, list[Event]]:
    groups: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if "no_timestamp" in e.tags:
            continue
        key = _group_key(e, group_by)
        if key is not None:
            groups[key].append(e)
    return groups


def _threshold(events: list[Event], count: int, window: float) -> list[Event]:
    marked: set[int] = set()
    left = 0
    for right in range(len(events)):
        while (events[right].timestamp - events[left].timestamp).total_seconds() > window:
            left += 1
        if right - left + 1 >= count:
            marked.update(range(left, right + 1))
    return [events[i] for i in sorted(marked)]


def _distinct(events: list[Event], field_name: str, count: int, window: float) -> list[Event]:
    marked: set[int] = set()
    seen: Counter[str] = Counter()
    left = 0
    for right, e in enumerate(events):
        seen[_norm(_get(e, field_name))] += 1
        while (e.timestamp - events[left].timestamp).total_seconds() > window:
            k = _norm(_get(events[left], field_name))
            seen[k] -= 1
            if seen[k] == 0:
                del seen[k]
            left += 1
        if len(seen) >= count:
            marked.update(range(left, right + 1))
    return [events[i] for i in sorted(marked)]


def _then_cond(rule: Rule) -> dict[str, Any] | None:
    c = rule.correlate
    if not c or c.get("type") != "sequence":
        return None
    then = c.get("then")
    return dict(then.get("match", {})) if isinstance(then, dict) else {}


def _drop_vss_twins(events: list[Event]) -> list[Event]:
    """A shadow-copy event that duplicates a live one must not count twice; one without a live twin
    (e.g. a log deleted from the live system) is kept."""
    live = {(e.artifact, e.timestamp, e.message) for e in events if "vss" not in e.tags}
    return [e for e in events if "vss" not in e.tags or (e.artifact, e.timestamp, e.message) not in live]


def _correlate(rule: Rule, hits: list[Event], then_hits: list[Event]) -> Iterator[Finding]:
    hits, then_hits = _drop_vss_twins(hits), _drop_vss_twins(then_hits)
    c = rule.correlate or {}
    window = float(c["window_seconds"])
    if c["type"] == "sequence":
        thens = _grouped(then_hits, c["group_by"])
        for key, group in _grouped(hits, c["group_by"]).items():
            for t in thens.get(key, []):
                before = [e for e in group
                          if e.timestamp < t.timestamp and (t.timestamp - e.timestamp).total_seconds() <= window]
                if len(before) >= int(c["min_count"]):
                    yield rule.finding(before + [t])
                    break
        return
    for _, group in sorted(_grouped(hits, c["group_by"]).items()):
        if c["type"] == "threshold":
            matched = _threshold(group, int(c["count"]), window)
        else:
            matched = _distinct(group, c["field"], int(c["count"]), window)
        if matched:
            yield rule.finding(matched)


@register
class BuiltinRules(DetectionModule):
    meta = ModuleMeta(
        name="builtin_rules",
        description="Built-in detection rules (YAML) with threshold/distinct/sequence correlation",
        type=ModuleType.DETECTION,
    )

    def detect(self, store: EventStore, ctx: Context, errors: ErrorSink | None = None) -> Iterator[Finding]:
        rules = load_rules(errors=errors or (lambda m, s: None))
        artifacts = sorted({a for r in rules for a in r.artifacts})
        hits: dict[str, list[Event]] = defaultdict(list)
        then_hits: dict[str, list[Event]] = defaultdict(list)
        then_conds = {r.id: c for r in rules if (c := _then_cond(r)) is not None}
        for artifact in artifacts:
            relevant = [r for r in rules if artifact in r.artifacts]
            for e in store.iter_events(artifact=artifact):
                for r in relevant:
                    if r.matches(e):
                        hits[r.id].append(e)
                    cond = then_conds.get(r.id)
                    if cond is not None and _match_eq(e, cond):
                        then_hits[r.id].append(e)
        for r in rules:
            matched = hits.get(r.id)
            if not matched:
                continue
            if r.correlate:
                yield from _correlate(r, matched, then_hits.get(r.id, []))
            else:
                yield r.finding(_drop_vss_twins(matched))
