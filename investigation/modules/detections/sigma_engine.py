"""A native Sigma evaluator: pySigma parses the rules, we compile the condition tree to Python matchers.

Events are routed by (Channel, EventID) so every event is only tested against rules for its log source.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from investigation.core.models import Event, Severity

log = logging.getLogger("investigation")

SYSMON = "Microsoft-Windows-Sysmon/Operational"
PS_OP = "Microsoft-Windows-PowerShell/Operational"
LEVELS = {"informational": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
          "high": Severity.HIGH, "critical": Severity.CRITICAL}
SKIP_STATUS = {"deprecated", "unsupported"}
_INTEGRITY = {"s-1-16-4096": "Low", "s-1-16-8192": "Medium", "s-1-16-8448": "Medium Plus",
              "s-1-16-12288": "High", "s-1-16-16384": "System"}


def _user_4688(e: Event) -> str | None:
    """Account of the NEW process (Win10+ Target*), falling back to the creator (Subject*)."""
    f = e.fields
    for dom, user in (("TargetDomainName", "TargetUserName"), ("SubjectDomainName", "SubjectUserName")):
        u = f.get(user)
        if u not in (None, "", "-"):
            d = f.get(dom)
            return f"{d}\\{u}" if d not in (None, "", "-") else str(u)
    return None


def _integrity_4688(e: Event) -> str | None:
    label = e.fields.get("MandatoryLabel")
    return _INTEGRITY.get(str(label).casefold()) if label else None


FIELD_MAP_4688: dict[str, Any] = {
    "Image": "NewProcessName", "ParentImage": "ParentProcessName", "CommandLine": "CommandLine",
    "User": _user_4688, "IntegrityLevel": _integrity_4688, "LogonId": "TargetLogonId",
}
FIELDS_4688 = set(FIELD_MAP_4688) | {
    "EventID", "Channel", "Provider_Name", "Computer", "NewProcessName", "ParentProcessName", "SubjectUserName",
    "SubjectDomainName", "SubjectLogonId", "SubjectUserSid", "TargetUserName", "TargetDomainName",
    "TargetLogonId", "TargetUserSid", "MandatoryLabel", "TokenElevationType",
}

Route = tuple[str, int | None, bool]


def _sysmon(*ids: int) -> list[Route]:
    return [(SYSMON, i, False) for i in ids]


SERVICES: dict[str, list[Route]] = {
    "security": [("Security", None, False)],
    "system": [("System", None, False)],
    "application": [("Application", None, False)],
    "sysmon": [(SYSMON, None, False)],
    "powershell": [(PS_OP, None, False), ("Windows PowerShell", None, False)],
    "powershell-classic": [("Windows PowerShell", None, False)],
    "windefend": [("Microsoft-Windows-Windows Defender/Operational", None, False)],
    "taskscheduler": [("Microsoft-Windows-TaskScheduler/Operational", None, False)],
    "wmi": [("Microsoft-Windows-WMI-Activity/Operational", None, False)],
    "terminalservices-localsessionmanager": [
        ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", None, False)],
    "bits-client": [("Microsoft-Windows-Bits-Client/Operational", None, False)],
    "codeintegrity-operational": [("Microsoft-Windows-CodeIntegrity/Operational", None, False)],
    "firewall-as": [("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", None, False)],
}
CATEGORIES: dict[str, list[Route]] = {
    "process_creation": _sysmon(1) + [("Security", 4688, True)],
    "network_connection": _sysmon(3),
    "process_termination": _sysmon(5),
    "driver_load": _sysmon(6),
    "image_load": _sysmon(7),
    "create_remote_thread": _sysmon(8),
    "raw_access_thread": _sysmon(9),
    "process_access": _sysmon(10),
    "file_event": _sysmon(11),
    "registry_add": _sysmon(12),
    "registry_delete": _sysmon(12),
    "registry_set": _sysmon(13),
    "registry_rename": _sysmon(14),
    "registry_event": _sysmon(12, 13, 14),
    "create_stream_hash": _sysmon(15),
    "pipe_created": _sysmon(17, 18),
    "wmi_event": _sysmon(19, 20, 21),
    "dns_query": _sysmon(22),
    "file_delete": _sysmon(23, 26),
    "process_tampering": _sysmon(25),
    "file_executable_detected": _sysmon(29),
    "ps_script": [(PS_OP, 4104, False)],
    "ps_module": [(PS_OP, 4103, False)],
    "ps_classic_start": [("Windows PowerShell", 400, False)],
}


class UnsupportedSigma(Exception):
    pass


Matcher = Callable[[Event, dict[str, str]], bool]


@dataclass
class CompiledRule:
    id: str
    title: str
    level: Severity
    mitre: tuple[str, ...]
    description: str
    routes: list[Route]
    matcher: Matcher
    path: str
    tactics: tuple[str, ...] = ()

    def matches(self, event: Event, mapping: dict[str, str]) -> bool:
        return self.matcher(event, mapping)


def _field_values(event: Event, field: str, mapping: dict[str, Any]) -> list[Any]:
    name = mapping.get(field, field)
    if callable(name):
        v = name(event)
    else:
        v = event.fields.get(name)
        if v is None and name != field:
            v = event.fields.get(field)
    return [] if v is None else [v]


def _py_regex(sre: Any, extra: int = 0) -> re.Pattern[str]:
    """pySigma SigmaRegularExpression -> compiled Python regex (its compile() only validates)."""
    flags = extra
    for flag in getattr(sre, "flags", ()) or ():
        flags |= sre.sigma_to_python_flags[flag]
    return re.compile(str(sre.regexp), flags)


def _compile_value(value: Any) -> Callable[[Any], bool]:
    from sigma import types as st

    expansion = getattr(st, "SigmaExpansion", None)
    if expansion is not None and isinstance(value, expansion):
        variants = [_compile_value(v) for v in value.values]
        return lambda v: any(c(v) for c in variants)
    if isinstance(value, st.SigmaRegularExpression):
        pattern = _py_regex(value, re.DOTALL)
        return lambda v: v is not None and pattern.search(str(v)) is not None
    if isinstance(value, st.SigmaString):
        if value.contains_placeholder():
            raise UnsupportedSigma("placeholder")
        flags = re.DOTALL if isinstance(value, getattr(st, "SigmaCasedString", ())) else re.DOTALL | re.IGNORECASE
        pattern = _py_regex(value.to_regex(), flags)
        if not value.contains_special() and flags & re.IGNORECASE:
            plain = "".join(p for p in value.s if isinstance(p, str)).casefold()
            return lambda v: v is not None and str(v).casefold() == plain
        return lambda v: v is not None and pattern.fullmatch(str(v)) is not None
    if isinstance(value, st.SigmaNumber):
        n = value.number

        def num(v: Any) -> bool:
            try:
                return v is not None and float(v) == float(n)
            except (TypeError, ValueError):
                return str(v).strip() == str(n)
        return num
    if isinstance(value, st.SigmaBool):
        b = value.boolean
        return lambda v: str(v).strip().casefold() in (("true", "1") if b else ("false", "0"))
    if isinstance(value, st.SigmaNull):
        return lambda v: v is None or str(v) == ""
    raise UnsupportedSigma(type(value).__name__)


def _compile_condition(node: Any) -> Matcher:
    from sigma import conditions as sc
    from sigma import types as st

    if isinstance(node, sc.ConditionAND):
        parts = [_compile_condition(a) for a in node.args]
        return lambda e, m: all(p(e, m) for p in parts)
    if isinstance(node, sc.ConditionOR):
        parts = [_compile_condition(a) for a in node.args]
        return lambda e, m: any(p(e, m) for p in parts)
    if isinstance(node, sc.ConditionNOT):
        inner = _compile_condition(node.args[0])
        return lambda e, m: not inner(e, m)
    if isinstance(node, sc.ConditionFieldEqualsValueExpression):
        field = node.field
        if isinstance(node.value, st.SigmaNull):
            return lambda e, m: not any(str(v) != "" for v in _field_values(e, field, m))
        check = _compile_value(node.value)
        return lambda e, m: any(check(v) for v in _field_values(e, field, m))
    if isinstance(node, sc.ConditionValueExpression):
        check = _compile_value(node.value)
        from sigma import types as st2

        if isinstance(node.value, st2.SigmaNumber):
            needle = str(node.value.number)
            check = lambda v: v is not None and needle in str(v)
        elif isinstance(node.value, st2.SigmaString):
            pat = _py_regex(node.value.to_regex(), re.IGNORECASE | re.DOTALL)
            check = lambda v: v is not None and pat.search(str(v)) is not None
        return lambda e, m: check(e.message) or any(check(v) for v in e.fields.values() if isinstance(v, str))
    raise UnsupportedSigma(type(node).__name__)


def _referenced_fields(node: Any) -> set[str]:
    out: set[str] = set()
    field = getattr(node, "field", None)
    if isinstance(field, str):
        out.add(field)
    for child in getattr(node, "args", []) or []:
        if not isinstance(child, str):
            out |= _referenced_fields(child)
    return out


def _routes(logsource: Any) -> list[Route] | None:
    if (logsource.product or "").casefold() != "windows":
        return None
    category = (logsource.category or "").casefold() or None
    service = (logsource.service or "").casefold() or None
    if category:
        routes = CATEGORIES.get(category)
        return list(routes) if routes else None
    if service:
        routes = SERVICES.get(service)
        return list(routes) if routes else None
    return None


def _mitre(tags: Iterable[Any]) -> tuple[str, ...]:
    out = []
    for t in tags:
        s = str(t).casefold()
        m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", s)
        if m:
            out.append(m.group(1).upper())
    return tuple(dict.fromkeys(out))


def _tactics(tags: Iterable[Any]) -> tuple[str, ...]:
    from investigation.core.attack import TACTIC_SLUGS

    out = []
    for t in tags:
        m = re.fullmatch(r"attack\.([a-z_-]+)", str(t).casefold())
        slug = m.group(1).replace("-", "_") if m else ""
        if slug in TACTIC_SLUGS and slug != "other":
            out.append(slug)
    return tuple(dict.fromkeys(out))


def compile_rule(rule: Any, path: str) -> CompiledRule:
    routes = _routes(rule.logsource)
    if routes is None:
        raise LookupError("logsource")
    if len(rule.detection.parsed_condition) != 1:
        raise UnsupportedSigma("multiple conditions")
    tree = rule.detection.parsed_condition[0].parse()
    matcher = _compile_condition(tree)
    fields = _referenced_fields(tree)
    if not fields <= FIELDS_4688:
        routes = [r for r in routes if not r[2]]
    level = LEVELS.get(str(getattr(rule.level, "name", rule.level) or "medium").casefold(), Severity.MEDIUM)
    return CompiledRule(
        id=str(rule.id) if rule.id else Path(path).stem,
        title=str(rule.title),
        level=level,
        mitre=_mitre(rule.tags or []),
        description=str(rule.description or "").strip(),
        routes=routes,
        matcher=matcher,
        path=path,
        tactics=_tactics(rule.tags or []),
    )


def iter_rule_files(paths: Iterable[Path]) -> Iterable[Path]:
    for p in paths:
        p = Path(p)
        if p.is_file() and p.suffix.casefold() in (".yml", ".yaml"):
            yield p
        elif p.is_dir():
            yield from sorted(x for x in p.rglob("*") if x.suffix.casefold() in (".yml", ".yaml") and x.is_file())


def load_sigma(paths: Iterable[Path], min_level: Severity) -> tuple[list[CompiledRule], dict[str, int]]:
    from sigma.collection import SigmaCollection
    from sigma.rule import SigmaRule

    stats = dict(loaded=0, skipped_unsupported=0, skipped_logsource=0, skipped_level=0, skipped_status=0,
                 invalid=0)
    rules: list[CompiledRule] = []
    seen: set[str] = set()
    for f in iter_rule_files(paths):
        try:
            collection = SigmaCollection.from_yaml(f.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:
            log.debug("invalid sigma file %s: %s", f, exc)
            stats["invalid"] += 1
            continue
        for rule in collection.rules:
            if not isinstance(rule, SigmaRule):
                stats["skipped_unsupported"] += 1
                continue
            status = str(getattr(rule.status, "name", rule.status) or "").casefold()
            if status in SKIP_STATUS:
                stats["skipped_status"] += 1
                continue
            try:
                compiled = compile_rule(rule, str(f))
            except LookupError:
                stats["skipped_logsource"] += 1
                continue
            except UnsupportedSigma as exc:
                log.debug("unsupported sigma rule %s: %s", f, exc)
                stats["skipped_unsupported"] += 1
                continue
            except Exception as exc:
                log.debug("cannot compile sigma rule %s: %s", f, exc)
                stats["invalid"] += 1
                continue
            if compiled.level < min_level:
                stats["skipped_level"] += 1
                continue
            if compiled.id in seen:
                continue
            seen.add(compiled.id)
            rules.append(compiled)
    stats["loaded"] = len(rules)
    return rules, stats
