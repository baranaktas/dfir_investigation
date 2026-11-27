import csv
import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from investigation.core.models import Event, EvidenceType, Finding, Severity
from investigation.core.preflight import PreflightReport
from investigation.core.requirements import CheckResult, Context, Status
from investigation.core.result import AnalysisResult
from investigation.core.store import EventStore
from investigation.modules.outputs.csv_out import CsvOutput
from investigation.modules.outputs.html_report import HtmlReport
from investigation.modules.outputs.jsonl_out import JsonlOutput

T0 = datetime(2024, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
XSS_IMG = "<script>alert(1)</script>"
XSS_MSG = "</script><img src=x onerror=alert(1)>"


def ev(i, **kw):
    base = dict(
        timestamp=T0 + timedelta(seconds=i), timestamp_desc="Event Logged", artifact="evtx",
        source_file="System.evtx", message=f"event {i}", host="PC01", user="bob",
        fields={"EventID": 7045}, evidence_type=EvidenceType.PERSISTENCE,
    )
    base.update(kw)
    return Event(**base)


@pytest.fixture
def result(tmp_path):
    store = EventStore(tmp_path / "db.sqlite")
    evil = ev(5, message=XSS_MSG, fields={"EventID": 7045, "ImagePath": XSS_IMG, "ServiceName": "evil"})
    store.add_many([ev(9), evil, ev(1, artifact="prefetch", evidence_type=EvidenceType.EXECUTION)])
    pre = PreflightReport()
    pre.results["framework"] = [CheckResult("python", Status.OK, "python 3.13", None, True)]
    pre.results["yara"] = [CheckResult("python package yara-python", Status.MISSING, "not installed",
                                       "pip install yara-python", True)]
    pre.skipped["yara"] = "not installed"
    findings = [
        Finding("INV-EVTX-004", "Service with suspicious image path", Severity.HIGH, "desc " + XSS_IMG,
                ("T1543.003",), [evil]),
        Finding("INV-EVTX-001", "Security event log cleared", Severity.CRITICAL, "cleared", ("T1070.001",), [ev(2)],
                note="note text"),
    ]
    return AnalysisResult(
        case={"input": "/evidence/x", "case_id": "2026-001", "examiner": "analyst",
              "started_utc": "2026-11-25T00:00:00+00:00", "finished_utc": "2026-11-25T00:01:00+00:00",
              "tool_version": "0.1.0"},
        store=store, findings=findings, preflight=pre,
        module_errors=[("evtx", "broken.evtx: bad header")], modules_run=["directory", "evtx"],
    )


def test_csv_sorted_and_header(result, tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    [path, _] = CsvOutput().write(result, out, Context())
    rows = list(csv.reader(path.open(encoding="utf-8")))
    assert rows[0] == ["timestamp", "timestamp_desc", "artifact", "evidence_type", "host", "user", "message",
                       "source_file"]
    assert [r[6] for r in rows[1:]] == ["event 1", XSS_MSG, "event 9"]


def test_jsonl_one_event_per_line_and_findings_json(result, tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    paths = JsonlOutput().write(result, out, Context())
    assert {p.name for p in paths} == {"events.jsonl", "findings.json", "stories.json"}
    lines = (out / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    assert json.loads(lines[0])["message"] == "event 1"
    findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    assert [f["rule_id"] for f in findings["findings"]] == ["INV-EVTX-001", "INV-EVTX-004"]
    assert findings["case"]["case_id"] == "2026-001"
    assert findings["preflight"]["skipped"] == {"yara": "not installed"}
    assert findings["module_errors"] == [{"module": "evtx", "message": "broken.evtx: bad header"}]


@pytest.fixture
def html(result, tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    [path] = HtmlReport().write(result, out, Context())
    assert path.name == "report.html"
    return path.read_text(encoding="utf-8")


def test_html_escapes_attacker_content(html):
    assert "<script>alert(1)" not in html
    assert "</script><img" not in html
    assert "onerror=alert(1)>" not in html
    assert len(re.findall(r"<script\b", html)) == 2


def test_html_contains_sections(html):
    for text in ("Findings", "Timeline", "Preflight", "Service with suspicious image path", "T1070.001",
                 "2026-001", "broken.evtx: bad header", "yara", "pip install yara-python", "note text",
                 "persistence"):
        assert text in html, text
    assert html.index("Service with suspicious image path") < html.index("Security event log cleared")


def test_html_has_no_external_resources(html):
    assert not re.search(r"""(src|href)\s*=\s*["']?https?://""", html, re.I)
    assert "@import" not in html


def test_html_timeline_truncation_note(result, tmp_path, monkeypatch):
    import investigation.modules.outputs.html_report as hr

    monkeypatch.setattr(hr, "TIMELINE_LIMIT", 2)
    out = tmp_path / "o2"
    out.mkdir()
    [path] = HtmlReport().write(result, out, Context())
    text = path.read_text(encoding="utf-8")
    assert "timeline.csv" in text
    assert "2 of 3" in text


def test_csv_neutralizes_formulas(tmp_path):
    store = EventStore(tmp_path / "db.sqlite")
    store.add_many([ev(0, message='=HYPERLINK("http://evil","x")', user="+cmd|' /C calc'!A0", host="@SUM(1)"),
                    ev(1, message="-2+3", user="\tTAB"), ev(2, message="normal text")])
    res = AnalysisResult(case={}, store=store, findings=[], preflight=PreflightReport())
    out = tmp_path / "out"
    out.mkdir()
    [path, _] = CsvOutput().write(res, out, Context())
    rows = list(csv.reader(path.open(encoding="utf-8")))
    assert rows[1][6] == "'=HYPERLINK(\"http://evil\",\"x\")"
    assert rows[1][5] == "'+cmd|' /C calc'!A0"
    assert rows[1][4] == "'@SUM(1)"
    assert rows[2][6] == "'-2+3"
    assert rows[2][5] == "'\tTAB"
    assert rows[3][6] == "normal text"
    assert rows[1][0].startswith("2024-")


def test_html_story_and_notes_escaped(tmp_path):
    from investigation.core.story import FileStory, SECTIONS

    store = EventStore(tmp_path / "db.sqlite")
    evil = ev(1, artifact="shimcache", message="<script>x</script>.exe seen")
    store.add_many([evil, ev(2, artifact="x", message="later", tags=("no_timestamp",),
                             timestamp=datetime(1970, 1, 1, tzinfo=timezone.utc), timestamp_desc="No Timestamp")])
    story = FileStory(name="<script>x</script>.exe", sections={s: [] for s in SECTIONS}, hashes={})
    story.sections["When did it run?"].append(evil)
    res = AnalysisResult(case={}, store=store, findings=[], preflight=PreflightReport(),
                         stories=[story], notes={"shimcache": "Shimcache does not prove execution."})
    out = tmp_path / "out"
    out.mkdir()
    [path] = HtmlReport().write(res, out, Context())
    html = path.read_text(encoding="utf-8")
    assert "<script>x</script>" not in html
    assert "File stories" in html and "Interpretation notes" in html
    assert "Shimcache does not prove execution." in html
    assert "no evidence found" in html


def test_no_timestamp_rendered_last(tmp_path):
    store = EventStore(tmp_path / "db.sqlite")
    store.add_many([ev(5, message="normal"),
                    ev(0, message="undated", tags=("no_timestamp",),
                       timestamp=datetime(1970, 1, 1, tzinfo=timezone.utc), timestamp_desc="No Timestamp")])
    rows = [e.message for e in store.iter_events()]
    assert rows == ["normal", "undated"]


def test_commands_csv_is_written_and_neutralised(tmp_path):
    store = EventStore(tmp_path / "c.sqlite")
    store.add_many([
        ev(1, artifact="powershell_history", fields={"command": "=cmd|' /c calc'"}, host=None),
        ev(2, artifact="powershell_history", fields={"command": "vssadmin delete shadows /all"}),
    ])
    res = AnalysisResult(case={}, store=store, findings=[], preflight=PreflightReport(), module_errors=[],
                         modules_run=[])
    out = tmp_path / "o"
    out.mkdir()
    paths = CsvOutput().write(res, out, Context())
    assert [p.name for p in paths] == ["timeline.csv", "commands.csv"]
    rows = list(csv.reader((out / "commands.csv").open(encoding="utf-8")))
    assert rows[0][:2] == ["time", "source"]
    assert sorted(r[5] for r in rows[1:]) == ["'=cmd|' /c calc'", "vssadmin delete shadows /all"]
    assert [r[7] for r in rows[1:] if "vssadmin" in r[5]] == ["INV-CMD-003"]
