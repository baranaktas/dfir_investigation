import json
import re
from datetime import datetime, timedelta, timezone

from investigation.core.allowlist import Suppressed
from investigation.core.grouping import group_cards, group_commands, key_of, timeline_summary
from investigation.core.models import Event, EvidenceType, Finding, Severity
from investigation.core.preflight import PreflightReport
from investigation.core.requirements import Context
from investigation.core.result import AnalysisResult
from investigation.core.store import EventStore
from investigation.modules.outputs.html_report import HtmlReport, commands_payload
from investigation.modules.outputs.jsonl_out import JsonlOutput

T0 = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)


def defender(i, threat, source="Microsoft-Windows-Windows Defender%4Operational.evtx"):
    return Event(timestamp=T0 + timedelta(minutes=i), timestamp_desc="Event Logged", artifact="evtx",
                 source_file=source, message=f"Defender detected {threat}", host="PC", user=None,
                 fields={"EventID": 1116, "Channel": "Microsoft-Windows-Windows Defender/Operational",
                         "ThreatName": threat}, evidence_type=EvidenceType.OTHER)


def shadow_case():
    events = []
    for t in range(17):
        for copy in range(72):
            src = f"vss:{copy}:Defender.evtx" if copy else "Defender.evtx"
            events.append(defender(t * 100 + copy, f"Threat{t}", src))
    return events


def make_result(tmp_path, findings, events=()):
    store = EventStore(tmp_path / "db")
    store.add_many(events)
    return AnalysisResult(case={"input": "/x", "case_id": "c", "examiner": "", "started_utc": "a", "finished_utc": "b",
                                "tool_version": "t"},
                          store=store, findings=findings, preflight=PreflightReport())


def test_defender_events_group_into_one_card_per_threat():
    events = shadow_case()
    f = Finding("INV-DEF-1", "Defender detected malware", Severity.HIGH, "d", ("T1204",), events)
    cards = group_cards([f])
    assert len(events) == 1224 and len(cards) == 17
    assert all(c.count == 72 for c in cards)
    card = next(c for c in cards if c.key == "Threat3")
    assert card.first == T0 + timedelta(minutes=300) and card.last == T0 + timedelta(minutes=371)
    assert "disk" in card.sources and any(s.startswith("vss") for s in card.sources)
    assert key_of(events[0]) == "Threat0"


def test_card_key_falls_back_to_service_command_image_and_user():
    def e(**fields):
        return Event(timestamp=T0, timestamp_desc="d", artifact="evtx", source_file="f", message="m", user="u",
                     fields=fields)
    assert key_of(e(ServiceName="svc")) == "svc"
    assert key_of(e(CommandLine="cmd /c x", Image="a.exe")) == "cmd /c x"
    assert key_of(e(NewProcessName="b.exe")) == "b.exe"
    assert key_of(e(TargetUserName="alice")) == "alice"
    assert key_of(e()) == "u"


def test_report_shows_one_card_per_key_and_findings_json_keeps_every_event(tmp_path):
    events = shadow_case()
    f = Finding("INV-DEF-1", "Defender detected malware", Severity.HIGH, "d", ("T1204",), events)
    r = make_result(tmp_path, [f], events)
    out = tmp_path / "out"
    out.mkdir()
    [path] = HtmlReport().write(r, out, Context())
    html = path.read_text(encoding="utf-8")
    assert "<h2>Findings (17)</h2>" in html
    assert html.count("Defender detected malware</strong>") == 17
    assert "72 event(s), first 2026-05-01T12:" in html
    JsonlOutput().write(r, out, Context())
    data = json.loads((out / "findings.json").read_text())
    assert sum(len(x["events"]) for x in data["findings"]) == 1224


def test_card_events_are_capped_but_counted(tmp_path):
    events = [defender(i, "One") for i in range(120)]
    r = make_result(tmp_path, [Finding("R", "t", Severity.HIGH, "d", (), events)], events)
    out = tmp_path / "out"
    out.mkdir()
    html = HtmlReport().write(r, out, Context())[0].read_text(encoding="utf-8")
    assert "120 event(s)" in html and "Showing 50 of 120 events" in html


def cmd_event(i, command, source_file="ConsoleHost_history.txt"):
    return Event(timestamp=T0 + timedelta(minutes=i), timestamp_desc="d", artifact="evtx", source_file=source_file,
                 message="m", host="PC", user="bob",
                 fields={"Channel": "Security", "EventID": 4688, "CommandLine": command,
                         "NewProcessName": "C:\\Windows\\System32\\cmd.exe", "NewProcessId": 1})


def test_identical_commands_collapse_with_count_first_last_and_sources(tmp_path):
    store = EventStore(tmp_path / "db")
    store.add_many([cmd_event(1, "whoami", "a.evtx"), cmd_event(5, "whoami", "b.evtx"), cmd_event(9, "whoami", "a.evtx"),
                    cmd_event(2, "hostname")])
    payload = commands_payload(store)
    assert payload["total"] == 4 and payload["distinct"] == 2 and len(payload["rows"]) == 2
    row = next(r for r in payload["rows"] if r[5] == "whoami")
    assert row[9] == 3
    assert row[0] == (T0 + timedelta(minutes=1)).isoformat() and row[10] == (T0 + timedelta(minutes=9)).isoformat()
    assert row[7] == "a.evtx, b.evtx"


def test_group_commands_keeps_first_appearance_order():
    class R:
        def __init__(self, c):
            self.command = c
    groups = group_commands([R("a"), R("b"), R("a")])
    assert [(g.command, g.count) for g in groups] == [("a", 2), ("b", 1)]


def test_timeline_summary_counts_per_artifact_and_day(tmp_path):
    store = EventStore(tmp_path / "db")
    def mk(day, artifact):
        return Event(timestamp=T0 + timedelta(days=day), timestamp_desc="d", artifact=artifact, source_file="f", message="m")
    undated = Event(timestamp=datetime(1970, 1, 1, tzinfo=timezone.utc), timestamp_desc="No Timestamp", artifact="mft",
                    source_file="f", message="m", tags=("no_timestamp",))
    store.add_many([mk(0, "evtx"), mk(0, "evtx"), mk(1, "evtx"), mk(0, "prefetch"), undated])
    summary = timeline_summary(store.day_counts())
    assert summary[0] == {"artifact": "evtx", "days": [("2026-05-01", 2), ("2026-05-02", 1)], "total": 3}
    assert {s["artifact"]: s["total"] for s in summary} == {"evtx": 3, "prefetch": 1, "mft": 1}
    assert summary[-1]["days"] == [("undated", 1)] or any(s["days"] == [("undated", 1)] for s in summary)


def test_report_has_timeline_summary_and_collapsed_rows(tmp_path):
    events = [defender(i, "T") for i in range(3)]
    r = make_result(tmp_path, [], events)
    out = tmp_path / "out"
    out.mkdir()
    html = HtmlReport().write(r, out, Context())[0].read_text(encoding="utf-8")
    assert "Summary per artifact and day" in html
    assert re.search(r'id="timeline-rows"', html)
    assert "2026-05-01: 3" in html


def test_report_lists_suppressed_events_with_reason(tmp_path):
    r = make_result(tmp_path, [])
    r.suppressed = [Suppressed("R1", "Title", "ServiceName", "value: Backup", "Company backup", 4)]
    out = tmp_path / "out"
    out.mkdir()
    html = HtmlReport().write(r, out, Context())[0].read_text(encoding="utf-8")
    assert "Suppressed by allowlist (4)" in html and "Company backup" in html
    JsonlOutput().write(r, out, Context())
    assert json.loads((out / "findings.json").read_text())["suppressed_by_allowlist"][0]["events"] == 4
