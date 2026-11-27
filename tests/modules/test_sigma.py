import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from investigation.core.models import Event, Severity
from investigation.core.requirements import Context
from investigation.core.store import EventStore
from investigation.modules.detections.sigma import SigmaDetection
from investigation.modules.detections.sigma_engine import load_sigma
from investigation.modules.parsers.evtx import EvtxParser
from investigation.modules.sources.directory import DirectoryEvidence

ROOT = Path(__file__).resolve().parent.parent
SIGMA_FIXTURES = ROOT / "fixtures" / "sigma"
EVTX = ROOT / "fixtures" / "evtx"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
T0 = datetime(2024, 5, 1, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))


def ev(i=0, **fields):
    fields.setdefault("Channel", "Security")
    return Event(timestamp=T0 + timedelta(seconds=i), timestamp_desc="Event Logged", artifact="evtx",
                 source_file="s.evtx", message=f"{fields.get('Channel')} {fields.get('EventID')}: x", fields=fields)


def write_rule(d: Path, name: str, body: str) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{name}.yml"
    p.write_text(body)
    return p


RULE = """title: Test {name}
id: {id}
status: test
level: {level}
tags: [attack.execution, attack.t1059.001]
logsource: {logsource}
detection:
{detection}
"""


def rule(d, name, detection, logsource="{product: windows, category: process_creation}", level="high",
         rid="00000000-0000-0000-0000-000000000001"):
    return write_rule(d, name, RULE.format(name=name, id=rid, level=level, logsource=logsource, detection=detection))


def detect(tmp_path, rules_dir, events, **opts):
    store = EventStore(tmp_path / f"db{time.monotonic_ns()}.sqlite")
    store.add_many(events)
    ctx = Context(allow_install=False, options={"sigma_paths": [str(rules_dir)], **opts})
    return list(SigmaDetection().detect(store, ctx, errors=lambda m, s: None))


def proc(i=0, image=r"C:\Windows\System32\cmd.exe", cmd="cmd", parent=r"C:\Windows\explorer.exe", **kw):
    return ev(i, EventID=1, Channel=SYSMON, Image=image, CommandLine=cmd, ParentImage=parent, **kw)


def test_compile_and_match_modifiers(tmp_path):
    d = tmp_path / "r"
    rule(d, "mods", """  sel_img:
    Image|endswith: ['\\\\powershell.exe', '\\\\pwsh.exe']
  sel_cli:
    CommandLine|contains|all: [' -enc ', 'hidden']
  sel_start:
    CommandLine|startswith: 'powershell'
  filter_re:
    ParentImage|re: '(?i)\\\\ccmexec\\.exe$'
  filter_null:
    User: null
  condition: all of sel_* and not filter_re and not filter_null""")
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    hit = proc(image=ps, cmd="powershell -w hidden -enc AAAA ", User="bob")
    assert len(detect(tmp_path, d, [hit])) == 1
    assert detect(tmp_path, d, [proc(image=ps, cmd="powershell -w hidden", User="bob")]) == []
    assert detect(tmp_path, d, [proc(image=ps, cmd="powershell -w hidden -enc AAAA ",
                                     parent=r"C:\x\CcmExec.exe", User="bob")]) == []
    assert detect(tmp_path, d, [proc(image=ps, cmd="powershell -w hidden -enc AAAA ")]) == []


def test_one_of_all_of_them_numbers_keywords(tmp_path):
    d = tmp_path / "r"
    rule(d, "oneof", """  a:
    EventID: 4625
  b:
    LogonType: 10
  condition: 1 of them""", logsource="{product: windows, service: security}", rid="00000000-0000-0000-0000-00000000000a")
    rule(d, "allof", """  a:
    EventID: 4625
  b:
    LogonType: 10
  condition: all of them""", logsource="{product: windows, service: security}", rid="00000000-0000-0000-0000-00000000000b")
    rule(d, "kw", """  keywords:
    - mimikatz
  condition: keywords""", logsource="{product: windows, service: security}", rid="00000000-0000-0000-0000-00000000000c")
    found = {f.title for f in detect(tmp_path, d, [ev(EventID=4625, LogonType=3)])}
    assert found == {"Test oneof"}
    found = {f.title for f in detect(tmp_path, d, [ev(EventID="4625", LogonType="10", Note="ran MIMIKATZ.exe")])}
    assert found == {"Test oneof", "Test allof", "Test kw"}


def test_4688_field_mapping(tmp_path):
    d = tmp_path / "r"
    rule(d, "map", """  sel:
    Image|endswith: '\\\\certutil.exe'
    ParentImage|endswith: '\\\\winword.exe'
  condition: sel""")
    e = ev(EventID=4688, NewProcessName=r"C:\Windows\System32\certutil.exe",
           ParentProcessName=r"C:\Office\WINWORD.EXE", CommandLine="certutil")
    assert len(detect(tmp_path, d, [e])) == 1


def test_routing_skips_other_channels(tmp_path):
    d = tmp_path / "r"
    rule(d, "sec", """  sel:
    EventID: 1102
  condition: sel""", logsource="{product: windows, service: security}")
    assert detect(tmp_path, d, [ev(EventID=1102, Channel="System")]) == []
    assert len(detect(tmp_path, d, [ev(EventID=1102, Channel="Security")])) == 1


def test_unsupported_counted(tmp_path):
    d = tmp_path / "r"
    rule(d, "cidr", """  sel:
    IpAddress|cidr: 10.0.0.0/8
  condition: sel""", logsource="{product: windows, service: security}", rid="00000000-0000-0000-0000-0000000000c1")
    rule(d, "fieldref", """  sel:
    TargetUserName|fieldref: SubjectUserName
  condition: sel""", logsource="{product: windows, service: security}", rid="00000000-0000-0000-0000-0000000000c2")
    rule(d, "nolog", """  sel:
    x: 1
  condition: sel""", logsource="{product: linux, service: auth}", rid="00000000-0000-0000-0000-0000000000c3")
    rules, stats = load_sigma([d], Severity.MEDIUM)
    assert rules == []
    assert stats["skipped_unsupported"] == 2
    assert stats["skipped_logsource"] == 1


def test_level_and_status_filters(tmp_path):
    d = tmp_path / "r"
    rule(d, "low", "  sel:\n    EventID: 1\n  condition: sel", level="low", rid="00000000-0000-0000-0000-0000000000d1")
    p = rule(d, "dep", "  sel:\n    EventID: 1\n  condition: sel", rid="00000000-0000-0000-0000-0000000000d2")
    p.write_text(p.read_text().replace("status: test", "status: deprecated"))
    rule(d, "ok", "  sel:\n    EventID: 1\n  condition: sel", rid="00000000-0000-0000-0000-0000000000d3")
    rules, stats = load_sigma([d], Severity.MEDIUM)
    assert [r.title for r in rules] == ["Test ok"]
    assert stats["skipped_level"] == 1 and stats["skipped_status"] == 1
    rules, _ = load_sigma([d], Severity.LOW)
    assert {r.title for r in rules} == {"Test ok", "Test low"}


def test_invalid_yaml_counted(tmp_path):
    d = tmp_path / "r"
    write_rule(d, "broken", "title: [unclosed\n")
    _, stats = load_sigma([d], Severity.MEDIUM)
    assert stats["invalid"] == 1


def test_real_sigmahq_rules_on_attack_samples(tmp_path):
    store = EventStore(tmp_path / "db.sqlite")
    store.add_many(EvtxParser().parse(DirectoryEvidence(EVTX), Context(), lambda m, s: None))
    ctx = Context(allow_install=False, options={"sigma_paths": [str(SIGMA_FIXTURES)]})
    findings = list(SigmaDetection().detect(store, ctx, errors=lambda m, s: None))
    titles = {f.title: f for f in findings}
    assert any("Cleared" in t for t in titles), titles.keys()
    comsvcs = [f for t, f in titles.items() if "Comsvcs" in t or "comsvcs" in t.lower()]
    assert comsvcs and comsvcs[0].mitre and all(m.startswith("T") for m in comsvcs[0].mitre)
    assert all(f.rule_id.startswith("SIGMA-") for f in findings)
    assert SigmaDetection.last_stats["loaded"] == 4


def test_performance(tmp_path):
    d = tmp_path / "r"
    for i in range(2000):
        rule(d, f"p{i}", f"""  sel:
    CommandLine|contains: 'needle{i} '
    Image|endswith: '\\\\tool{i}.exe'
  condition: sel""", rid=f"00000000-0000-0000-0000-{i:012d}")
    events = [proc(i, image=rf"C:\x\tool{i % 50}.exe", cmd=f"run needle{i % 3000} now") for i in range(20000)]
    start = time.monotonic()
    findings = detect(tmp_path, d, events)
    assert time.monotonic() - start < 180
    assert findings


def test_pipeline_reports_sigma_stats(tmp_path):
    import json

    from investigation.core.pipeline import analyze

    out = tmp_path / "out"
    analyze(EVTX, out, allow_install=False, options={"sigma_paths": [str(SIGMA_FIXTURES)]})
    data = json.loads((out / "findings.json").read_text())
    assert data["case"]["sigma"]["loaded"] == 4
    assert any(f["rule_id"].startswith("SIGMA-") for f in data["findings"])
    assert "Sigma: 4 rules loaded" in (out / "report.html").read_text()
