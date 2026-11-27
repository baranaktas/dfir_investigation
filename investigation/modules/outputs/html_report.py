"""report.html - a single self-contained report (no external resources, works offline)."""

from __future__ import annotations

import json
from collections import Counter
from datetime import timedelta
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from investigation.core.attack import TACTICS, primary_tactic, source_label, tactics_for
from investigation.core.models import Event, EvidenceType, Finding, Severity
from investigation.core.module import ModuleMeta, ModuleType, OutputModule
from investigation.core.registry import register
from investigation.core.requirements import Context
from investigation.core.store import EventStore
from investigation.core.frozen import resource

TEMPLATES = resource("templates")
TIMELINE_LIMIT = 200_000
GROUP_PAGE = 500
AROUND = timedelta(minutes=10)
AROUND_CAP = 50_000
FINDING_EVENT_LIMIT = 50


def safe_json(data: object) -> str:
    """JSON that is safe to embed inside <script type="application/json">."""
    return (
        json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace(" ", "\\u2028")
        .replace(" ", "\\u2029")
    )


TACTIC_NAMES = dict(TACTICS)
COLUMNS = ["Time (UTC)", "Artifact", "Evidence", "Source", "Host", "User", "Event", "File"]
EVIDENCE_ORDER = ("execution", "persistence", "network", "authentication", "user_activity", "file_access",
                  "existence", "device", "other")
assert set(EVIDENCE_ORDER) == {e.value for e in EvidenceType}


def group_findings(findings: list[Finding]) -> list[tuple[str, str, list[Finding]]]:
    """(slug, Name, findings) per ATT&CK tactic in kill-chain order; only non-empty groups.
    Input order (severity, descending) is kept inside a group."""
    buckets: dict[str, list[Finding]] = {}
    for f in findings:
        buckets.setdefault(primary_tactic(f), []).append(f)
    return [(slug, name, buckets[slug]) for slug, name in TACTICS if slug in buckets]


def _row(e: Event) -> list[str]:
    when = "\u2014" if "no_timestamp" in e.tags else e.timestamp.isoformat()
    return [when, e.artifact, str(e.evidence_type), source_label(e), e.host or "", e.user or "", e.message,
            e.source_file]


def _windows(findings: list[Finding]) -> list[tuple]:
    """Merged, time-ordered [start, end] windows (+-AROUND) around the dated events of all findings."""
    spans = sorted((e.timestamp - AROUND, e.timestamp + AROUND)
                   for f in findings for e in f.events if "no_timestamp" not in e.tags)
    merged: list[list] = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            if b > merged[-1][1]:
                merged[-1][1] = b
        else:
            merged.append([a, b])
    return [(a, b) for a, b in merged]


def timeline_payload(store: EventStore, findings: list[Finding], limit: int) -> dict:
    """Embedded timeline cut at `limit` rows: "around findings" first (at most AROUND_CAP rows), then the
    rest of the budget split evenly over the evidence groups; a group's unused share goes to later groups,
    and a second pass tops up groups that hit their share. Streamed from the store, never fully loaded."""
    seen: set[int] = set()
    by_id: dict[str, dict] = {}
    order: list[str] = []
    totals = store.evidence_counts()

    def take(gid: str, label: str, source, budget: int, total: int | None) -> int:
        rows = []
        for rid, e in source:
            if len(rows) >= budget:
                break
            if rid in seen:
                continue
            seen.add(rid)
            rows.append(_row(e))
        if rows:
            g = by_id.get(gid)
            if g is None:
                g = by_id[gid] = {"id": gid, "label": label, "rows": [], "total": total}
                order.append(gid)
            g["rows"].extend(rows)
        return len(rows)

    def around():
        for a, b in _windows(findings):
            yield from store.iter_with_id(start=a, end=b)

    def evidence(et: str, budget: int):
        return store.iter_with_id(evidence_type=et, limit=budget + len(seen))

    left = limit - take("around", "Around findings (\u00b110 min)", around(), min(AROUND_CAP, limit), None)
    share = left // len(EVIDENCE_ORDER)
    carry, hit = 0, []
    for et in EVIDENCE_ORDER:
        allowance = share + carry
        got = take(et, et.replace("_", " ").capitalize(), evidence(et, allowance), allowance, totals.get(et, 0))
        carry = allowance - got
        left -= got
        if got >= allowance:
            hit.append(et)
    for et in hit:
        if left <= 0:
            break
        left -= take(et, et.replace("_", " ").capitalize(), evidence(et, left), left, totals.get(et, 0))
    groups = [by_id[g] for g in order]
    groups.sort(key=lambda g: -1 if g["id"] == "around" else EVIDENCE_ORDER.index(g["id"]))
    return {"columns": COLUMNS, "groups": groups, "total": store.count(),
            "shown": sum(len(g["rows"]) for g in groups)}


def _manifest_summary(case: dict) -> dict[str, str]:
    """hostname/status/tool version from a collection package's manifest.json, when the input has one."""
    if not case.get("input"):
        return {}
    try:
        data = json.loads((Path(case["input"]) / "manifest.json").read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        return {k: str(data[k]) for k in ("hostname", "status", "tool_version") if data.get(k)}
    except (OSError, ValueError, TypeError):
        return {}


@register
class HtmlReport(OutputModule):
    meta = ModuleMeta(name="html_report", description="Self-contained HTML report", type=ModuleType.OUTPUT)

    def write(self, result, out_dir: Path, ctx: Context) -> list[Path]:
        env = Environment(
            loader=FileSystemLoader(str(TEMPLATES)),
            autoescape=select_autoescape(default=True, default_for_string=True),
        )
        findings = result.sorted_findings()
        store = result.store
        sev_counts = Counter(str(f.severity) for f in findings)
        env.globals["sources_of"] = lambda f: sorted({source_label(e) for e in f.events})
        env.globals["tactic_names_of"] = lambda f: [TACTIC_NAMES[t] if t in TACTIC_NAMES else t for t in tactics_for(f)]
        env.globals["sev_badges"] = lambda fs: [(str(s), n) for s in sorted(Severity, reverse=True)
                                                if (n := sum(1 for f in fs if f.severity == s))]
        payload = timeline_payload(store, findings, TIMELINE_LIMIT)
        html = env.get_template("report.html.j2").render(
            case=result.case,
            findings=findings,
            tactic_groups=group_findings(findings),
            finding_event_limit=FINDING_EVENT_LIMIT,
            severities=[str(s) for s in sorted(Severity, reverse=True)],
            severity_counts=sev_counts,
            source_counts=store.source_counts(),
            artifact_counts=store.artifact_counts(),
            evidence_counts=store.evidence_counts(),
            total_events=payload["total"],
            shown_events=payload["shown"],
            group_page=GROUP_PAGE,
            tl_groups=[(g["id"], g["label"], len(g["rows"]), g.get("total")) for g in payload["groups"]],
            timeline_json=safe_json(payload),
            manifest=_manifest_summary(result.case),
            preflight=result.preflight,
            module_errors=result.module_errors,
            modules_run=result.modules_run,
            notes=result.notes,
            stories=result.stories,
            story_sections=__import__("investigation.core.story", fromlist=["SECTIONS"]).SECTIONS,
        )
        path = Path(out_dir) / "report.html"
        path.write_text(html, encoding="utf-8")
        return [path]
