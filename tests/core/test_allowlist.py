import json
from datetime import datetime, timezone

import pytest

from investigation.core.allowlist import apply_allowlist, load_allowlist, parse_entry
from investigation.core.models import Event, Finding, Severity

T = datetime(2026, 5, 1, tzinfo=timezone.utc)


def ev(**fields):
    return Event(timestamp=T, timestamp_desc="d", artifact="evtx", source_file="f", message="m", user="bob",
                 fields=fields)


def finding(rule, *events):
    return Finding(rule, f"t {rule}", Severity.HIGH, "d", (), list(events))


def entries(*raws):
    return [parse_entry(r, "t") for r in raws]


def test_exact_value_is_case_insensitive_and_removes_only_matching_events():
    f = finding("R1", ev(ServiceName="Backup"), ev(ServiceName="evil"))
    kept, sup = apply_allowlist([f], entries({"rule": "R1", "field": "ServiceName", "value": "backup", "reason": "agent"}))
    assert [e.fields["ServiceName"] for e in kept[0].events] == ["evil"]
    assert len(f.events) == 2
    assert [(s.rule_id, s.count, s.reason) for s in sup] == [("R1", 1, "agent")]


def test_finding_without_remaining_events_is_dropped_but_listed():
    kept, sup = apply_allowlist([finding("R1", ev(a="x"), ev(a="x"))],
                                entries({"rule": "*", "field": "a", "value": "x", "reason": "ok"}))
    assert kept == [] and sup[0].count == 2


def test_regex_and_rule_scope():
    f1, f2 = finding("R1", ev(Image=r"C:\Tools\a.exe")), finding("R2", ev(Image=r"C:\Tools\a.exe"))
    kept, sup = apply_allowlist([f1, f2], entries({"rule": "R1", "field": "Image", "regex": r"^C:\\Tools\\", "reason": "tools"}))
    assert [f.rule_id for f in kept] == ["R2"]
    assert sup[0].pattern.startswith("regex:")


def test_event_attribute_fields_and_missing_fields():
    f = finding("R1", ev(a="x"))
    kept, _ = apply_allowlist([f], entries({"rule": "R1", "field": "user", "value": "bob", "reason": "r"}))
    assert kept == []
    kept, sup = apply_allowlist([f], entries({"rule": "R1", "field": "nope", "value": "x", "reason": "r"}))
    assert len(kept) == 1 and sup == []


@pytest.mark.parametrize("raw", [
    {"rule": "R1", "field": "a", "reason": "r"},
    {"rule": "R1", "field": "a", "value": "x", "regex": "y", "reason": "r"},
    {"rule": "R1", "field": "a", "value": "x"},
    {"rule": "R1", "field": "a", "regex": "(", "reason": "r"},
])
def test_invalid_entries_rejected(raw):
    with pytest.raises(ValueError):
        parse_entry(raw, "t")


def test_load_reports_bad_entries_and_keeps_good_ones(tmp_path):
    f = tmp_path / "a.yaml"
    f.write_text("- {rule: R1, field: a, value: x, reason: ok}\n- {rule: R1, field: a}\n")
    errs = []
    got = load_allowlist([f, tmp_path / "missing.yaml"], lambda m, s: errs.append((m, s)))
    assert len(got) == 1 and len(errs) == 2


def test_pipeline_lists_suppressed_events(tmp_path, monkeypatch):
    from investigation.core.pipeline import analyze

    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "evidence.txt").write_text("x")
    allow = tmp_path / "allow.yaml"
    allow.write_text("- {rule: '*', field: a, value: x, reason: lab machine}\n")
    out = tmp_path / "out"
    result = analyze(pkg, out, profile="triage", options={"allowlist_files": [str(allow)]})
    assert result.suppressed == []
    assert "Suppressed by allowlist (0)" in (out / "report.html").read_text(encoding="utf-8")
    assert json.loads((out / "findings.json").read_text())["suppressed_by_allowlist"] == []
