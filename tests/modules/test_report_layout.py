"""Layout of the collapsible HTML report: tactic groups, lazy timeline, safe DOM."""
import json
import re
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser

import pytest

from investigation.core.models import Event, EvidenceType, Finding, Severity
from investigation.core.preflight import PreflightReport
from investigation.core.requirements import Context
from investigation.core.result import AnalysisResult
from investigation.core.store import EventStore
from investigation.modules.outputs import html_report as hr
from investigation.modules.outputs.html_report import HtmlReport, group_findings, timeline_payload

T0 = datetime(2024, 5, 1, 12, 0, 0, tzinfo=timezone.utc)


def ev(minutes=0, **kw):
    base = dict(timestamp=T0 + timedelta(minutes=minutes), timestamp_desc="Event Logged", artifact="evtx",
                source_file="System.evtx", message=f"event {minutes}", host="PC01", user="bob",
                evidence_type=EvidenceType.PERSISTENCE)
    base.update(kw)
    return Event(**base)


def fnd(rule, sev, mitre=(), events=(), tactics=(), title=None):
    return Finding(rule, title or f"title {rule}", sev, "desc " + rule, tuple(mitre), list(events), tactics=tuple(tactics))


class Doc(HTMLParser):
    """Collects every <details> with its attributes and summary text."""

    def __init__(self, html):
        super().__init__()
        self.details = []
        self._in_summary = False
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "details":
            self.details.append({"attrs": a, "classes": (a.get("class") or "").split(), "summary": "", "open": "open" in a})
        elif tag == "summary":
            self._in_summary = True

    def handle_endtag(self, tag):
        if tag == "summary":
            self._in_summary = False

    def handle_data(self, data):
        if self._in_summary and self.details:
            self.details[-1]["summary"] += data

    def by_class(self, cls):
        return [d for d in self.details if cls in d["classes"]]

    def by_id(self, id_):
        return [d for d in self.details if d["attrs"].get("id") == id_]


def render(tmp_path, findings, events=(), **kw):
    store = EventStore(tmp_path / "db.sqlite")
    store.add_many(events)
    res = AnalysisResult(case={"case_id": "C1", "started_utc": "2026-01-01T00:00:00+00:00"}, store=store,
                         findings=list(findings), preflight=PreflightReport(), **kw)
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    [path] = HtmlReport().write(res, out, Context())
    return path.read_text(encoding="utf-8")


def test_findings_grouped_by_tactic_in_killchain_order(tmp_path):
    fs = [fnd("A", Severity.LOW), fnd("B", Severity.HIGH, ["T1070.001"]), fnd("C", Severity.HIGH, ["T1543.003"])]
    names = [s.split("(")[0].strip() for s in
             (d["summary"].strip() for d in Doc(render(tmp_path, fs)).by_class("tactic"))]
    assert names == ["Persistence", "Defense Evasion", "Other"]
    groups = group_findings(sorted(fs, key=lambda f: -f.severity))
    assert [g[0] for g in groups] == ["persistence", "defense_evasion", "other"]


def test_high_findings_open_low_closed(tmp_path):
    fs = [fnd("HI", Severity.HIGH, title="HighOne"), fnd("CR", Severity.CRITICAL, title="CritOne"),
          fnd("LO", Severity.LOW, title="LowOne"), fnd("ME", Severity.MEDIUM, title="MedOne")]
    doc = Doc(render(tmp_path, fs))
    state = {k: next(d["open"] for d in doc.by_class("finding") if k in d["summary"])
             for k in ("HighOne", "CritOne", "LowOne", "MedOne")}
    assert state == {"HighOne": True, "CritOne": True, "LowOne": False, "MedOne": False}
    assert all(d["open"] for d in doc.by_class("tactic"))


def test_sections_collapsed_by_default(tmp_path):
    doc = Doc(render(tmp_path, [fnd("A", Severity.HIGH)], [ev(0)], notes={"evtx": "caveat"}))
    for id_ in ("timeline", "stories", "notes", "technical"):
        [d] = doc.by_id(id_)
        assert not d["open"], id_


def test_around_findings_group_first(tmp_path):
    hit, near, far = ev(0, message="hit"), ev(5, message="near"), ev(30, message="far")
    store = EventStore(tmp_path / "db.sqlite")
    store.add_many([hit, near, far])
    payload = timeline_payload(store, [fnd("A", Severity.HIGH, events=[hit])], 100)
    assert payload["groups"][0]["id"] == "around"
    around = [r[6] for r in payload["groups"][0]["rows"]]
    assert around == ["hit", "near"]
    rest = [r[6] for g in payload["groups"][1:] for r in g["rows"]]
    assert rest == ["far"]
    assert payload["total"] == 3 and payload["shown"] == 3


def test_timeline_groups_render_lazily_and_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(hr, "TIMELINE_LIMIT", 10)
    html = render(tmp_path, [], [ev(i, message=f"row{i}") for i in range(25)])
    assert "Showing 10 of 25" in html and "timeline.csv" in html
    m = re.search(r'<tbody[^>]*>(.*?)</tbody>', html, re.S)
    assert m is None or "<tr" not in m.group(1)
    data = json.loads(re.search(r'id="timeline-data">(.*?)</script>', html, re.S).group(1))
    assert data["shown"] == 10 and data["total"] == 25
    assert sum(len(g["rows"]) for g in data["groups"]) == 10
    assert "Timeline needs JavaScript; see timeline.csv" in html


def test_around_cut_first(tmp_path):
    store = EventStore(tmp_path / "db.sqlite")
    evs = [ev(i, message=f"m{i}") for i in range(5)] + [ev(300, message="far")]
    store.add_many(evs)
    payload = timeline_payload(store, [fnd("A", Severity.HIGH, events=[evs[0]])], 3)
    assert [r[6] for r in payload["groups"][0]["rows"]] == ["m0", "m1", "m2"]
    assert payload["shown"] == 3 and len(payload["groups"]) == 1


def test_no_unsafe_dom_apis():
    tpl = (hr.TEMPLATES / "report.html.j2").read_text(encoding="utf-8")
    script = tpl[tpl.rindex("<script>"):]
    for bad in ("innerHTML", "insertAdjacentHTML", "eval(", "document.write", "outerHTML"):
        assert bad not in script, bad


def test_hostile_message_escaped(tmp_path):
    msg = "</script><img src=x onerror=alert(1)>"
    bad = ev(0, message=msg)
    html = render(tmp_path, [fnd("A", Severity.HIGH, events=[bad])], [bad])
    assert "</script><img" not in html and "<img src=x" not in html
    assert len(re.findall(r"<script\b", html)) == 2
    assert "\\u003c/script" in html


def test_no_findings_text(tmp_path):
    html = render(tmp_path, [])
    assert "No findings" in html
    assert Doc(html).by_class("tactic") == []


def test_source_badges(tmp_path):
    a = ev(0, source_file="vss:3:C:/Windows/System32/winevt/Logs/System.evtx")
    b = ev(1, artifact="live_services", source_file="live")
    html = render(tmp_path, [fnd("A", Severity.HIGH, events=[a, b])], [a, b])
    assert "vss:3" in html and "live" in html
    assert re.search(r'class="[^"]*src[^"]*"[^>]*>vss:3<', html)


def test_severity_order_within_tactic(tmp_path):
    fs = [fnd("L", Severity.LOW, ["T1070.001"], title="LowFirst"), fnd("C", Severity.CRITICAL, ["T1070.001"], title="CritSecond")]
    html = render(tmp_path, fs)
    assert html.index("CritSecond") < html.index("LowFirst")


def test_manifest_summary_robust(tmp_path, monkeypatch):
    d = tmp_path / "pkg"
    d.mkdir()
    (d / "manifest.json").write_text("[1, 2]", encoding="utf-8")
    assert hr._manifest_summary({"input": str(d)}) == {}
    (d / "manifest.json").write_text('{"hostname": "H1", "status": "ok"}', encoding="utf-8")
    assert hr._manifest_summary({"input": str(d)}) == {"hostname": "H1", "status": "ok"}
    (tmp_path / "manifest.json").write_text('{"hostname": "CWD"}', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert hr._manifest_summary({"input": ""}) == {}
    assert hr._manifest_summary({}) == {}


def test_undated_events_last_in_group_and_limit(tmp_path):
    store = EventStore(tmp_path / "db.sqlite")
    store.add_many([ev(1, message="late"), ev(0, message="early"),
                    ev(0, message="undated", tags=("no_timestamp",),
                       timestamp=datetime(1970, 1, 1, tzinfo=timezone.utc))])
    rows = timeline_payload(store, [], 100)["groups"][0]["rows"]
    assert [r[6] for r in rows] == ["early", "late", "undated"]
    assert [r[6] for r in timeline_payload(store, [], 2)["groups"][0]["rows"]] == ["early", "late"]
    plan = " ".join(str(r) for r in store._conn.execute(
        "EXPLAIN QUERY PLAN SELECT id FROM events WHERE evidence_type='persistence' ORDER BY timestamp, id"))
    assert "idx_events_et" in plan and "TEMP B-TREE" not in plan


def test_page_size_comes_from_python(tmp_path, monkeypatch):
    monkeypatch.setattr(hr, "GROUP_PAGE", 7)
    html = render(tmp_path, [], [ev(0)])
    assert 'data-page="7"' in html and "Show 7 more" in html


def _store_with(tmp_path, events):
    store = EventStore(tmp_path / "db.sqlite")
    store.add_many(events)
    return store


def test_around_group_cut_at_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(hr, "AROUND_CAP", 5)
    evs = [ev(0, message=f"m{i}", timestamp=T0 + timedelta(seconds=i)) for i in range(20)]
    p = timeline_payload(_store_with(tmp_path, evs), [fnd("A", Severity.HIGH, events=[evs[0]])], 100)
    assert len(p["groups"][0]["rows"]) == 5 and p["groups"][0]["id"] == "around"
    assert p["shown"] == 20


def test_evidence_groups_get_rows_when_around_is_huge(tmp_path, monkeypatch):
    monkeypatch.setattr(hr, "AROUND_CAP", 10)
    types = list(EvidenceType)
    evs = [ev(0, message=f"x{i}", evidence_type=types[i % len(types)],
              timestamp=T0 + timedelta(seconds=i)) for i in range(400)]
    p = timeline_payload(_store_with(tmp_path, evs), [fnd("A", Severity.HIGH, events=[evs[0]])], 100)
    ids = [g["id"] for g in p["groups"]]
    assert ids[0] == "around" and len(ids) == 1 + len(types)
    assert all(len(g["rows"]) >= 1 for g in p["groups"][1:])
    assert p["shown"] == 100
    assert all(g["total"] for g in p["groups"][1:])


def test_unused_share_is_redistributed(tmp_path):
    ex = [ev(0, message=f"e{i}", evidence_type=EvidenceType.EXECUTION, timestamp=T0 + timedelta(hours=i))
          for i in range(50)]
    ps = [ev(0, message="p", evidence_type=EvidenceType.PERSISTENCE, timestamp=T0 + timedelta(hours=100))]
    p = timeline_payload(_store_with(tmp_path, ex + ps), [], 18)
    sizes = {g["id"]: len(g["rows"]) for g in p["groups"]}
    assert sizes == {"execution": 17, "persistence": 1}
    times = [r[0] for r in p["groups"][0]["rows"]]
    assert times == sorted(times)


def test_group_summary_shows_x_of_y(tmp_path, monkeypatch):
    monkeypatch.setattr(hr, "TIMELINE_LIMIT", 9)
    html = render(tmp_path, [], [ev(i) for i in range(30)])
    assert "(showing 9 of 30)" in html


def _cmd(minutes, command, artifact="powershell_history", **fields):
    return ev(minutes, artifact=artifact, evidence_type=EvidenceType.USER_ACTIVITY, fields={"command": command, **fields})


def test_commands_section_between_findings_and_timeline(tmp_path):
    long = "A" * 1000
    events = [_cmd(0, "Get-ChildItem"), _cmd(1, "vssadmin delete shadows /all /quiet"), _cmd(2, long),
              ev(3, source_file="b/c.evtx", artifact="evtx", fields={"Channel": "Microsoft-Windows-PowerShell/Operational",
                                                                 "EventID": 4104, "ScriptBlockText": "ipconfig /all"})]
    html = render(tmp_path, [], events)
    assert "Commands (4)" in html
    assert html.index('id="commands"') < html.index('id="timeline"')
    data = json.loads(re.search(r'id="timeline-data">(.*?)</script>', html, re.S).group(1))
    rows = data["commands"]["rows"]
    assert data["commands"]["total"] == 4 and len(re.findall(r"<script\b", html)) == 2
    by_cmd = {r[5]: r for r in rows}
    assert by_cmd["vssadmin delete shadows /all /quiet"][8] == "INV-CMD-003"
    assert by_cmd["Get-ChildItem"][8] == "" and by_cmd["ipconfig /all"][8] == ""
    assert by_cmd["A" * 300][6] == "A" * 700
    assert rows[0][1] == "PowerShell 4104" and rows[0][0].startswith("2024-05-01")
    assert all(r[0] == "—" for r in rows[1:])


def test_commands_payload_keeps_suspicious_rows_over_the_limit(tmp_path):
    store = EventStore(tmp_path / "db.sqlite")
    store.add_many([_cmd(i, f"echo {i}") for i in range(5)] + [_cmd(9, "wevtutil cl Security")])
    payload = hr.commands_payload(store, limit=3)
    assert payload["total"] == 6 and len(payload["rows"]) == 3
    assert any(r[5] == "wevtutil cl Security" for r in payload["rows"])
