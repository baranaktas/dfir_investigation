"""Regression tests: output paths, EVTX truncation, rule loading, field aliases."""
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from investigation.core.models import Event
from investigation.core.pipeline import OutputDirError, analyze
from investigation.core.requirements import Context
from investigation.core.store import EventStore
from investigation.modules.detections.builtin import BuiltinRules
from investigation.modules.parsers.evtx import EvtxParser, normalize_fields
from investigation.modules.sources.directory import DirectoryEvidence

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "evtx"
T0 = datetime(2024, 5, 1, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))


def rule_ids(tmp_path, events):
    store = EventStore(tmp_path / "r.sqlite")
    store.add_many(events)
    return {f.rule_id for f in BuiltinRules().detect(store, Context())}


def ev(**fields):
    fields.setdefault("Channel", "Security")
    return Event(timestamp=T0, timestamp_desc="Event Logged", artifact="evtx", source_file="s.evtx",
                 message="m", fields=fields)


def test_output_inside_input_with_different_case(tmp_path):
    ev_dir = tmp_path / "ev"
    ev_dir.mkdir()
    if not (tmp_path / "EV").exists():
        pytest.skip("case-sensitive filesystem")
    with pytest.raises(OutputDirError):
        analyze(ev_dir, tmp_path / "EV" / "out", allow_install=False)
    assert not (ev_dir / "out").exists()


@pytest.mark.parametrize("size", [4200, 70000])
def test_truncated_evtx_reported(tmp_path, size):
    data = (FIXTURES / "1102_security_log_cleared.evtx").read_bytes()[:size]
    (tmp_path / "cut.evtx").write_bytes(data)
    errors = []
    list(EvtxParser().parse(DirectoryEvidence(tmp_path), Context(), lambda m, s: errors.append(s)))
    assert any("cut.evtx" in e and "truncated" in e for e in errors), errors


def test_complete_evtx_not_reported_truncated(tmp_path):
    errors = []
    list(EvtxParser().parse(DirectoryEvidence(FIXTURES), Context(), lambda m, s: errors.append(s)))
    assert errors == []


def test_bad_user_rule_file_does_not_disable_builtin(tmp_path, monkeypatch):
    home = tmp_path / "h"
    (home / "rules").mkdir(parents=True)
    (home / "rules" / "bad.yaml").write_text("- id: X\n  severity: low\n")
    monkeypatch.setenv("INVESTIGATION_HOME", str(home))
    store = EventStore(tmp_path / "r.sqlite")
    store.add_many([ev(EventID=1102)])
    errors = []
    found = {f.rule_id for f in BuiltinRules().detect(store, Context(), errors=lambda m, s: errors.append(s))}
    assert "INV-EVTX-001" in found
    assert any("bad.yaml" in e for e in errors)


def test_admin_share_rule_ignores_ipc(tmp_path):
    assert "INV-EVTX-021" not in rule_ids(tmp_path / "a", [ev(EventID=5140, ShareName="\\\\*\\IPC$")])
    assert "INV-EVTX-021" in rule_ids(tmp_path / "b", [ev(EventID=5140, ShareName="\\\\*\\ADMIN$")])
    assert "INV-EVTX-021" in rule_ids(tmp_path / "c", [ev(EventID=5145, ShareName="\\\\*\\C$")])


@pytest.fixture(autouse=True)
def _dirs(tmp_path):
    for d in "abcd":
        (tmp_path / d).mkdir()


def test_field_name_aliases():
    f = normalize_fields({"New Value": "HKLM\\...\\Exclusions\\Paths\\C:\\x", "EventID": 5007})
    assert f["NewValue"].startswith("HKLM")
    f = normalize_fields({"EventID": 4697, "ServiceFileName": "cmd.exe /c evil"})
    assert f["ImagePath"] == "cmd.exe /c evil"


def test_unreadable_directory_reported(tmp_path):
    if not hasattr(os, "geteuid"):
        pytest.skip("POSIX permissions only (chmod cannot lock a directory on Windows)")
    if os.geteuid() == 0:
        pytest.skip("root can read everything")
    src = tmp_path / "ev"
    shutil.copytree(FIXTURES, src)
    locked = src / "locked"
    locked.mkdir()
    locked.chmod(0)
    try:
        result = analyze(src, tmp_path / "out", allow_install=False)
    finally:
        locked.chmod(0o755)
    assert any("locked" in msg for _, msg in result.module_errors), result.module_errors


def test_unwritable_output_exit_2(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    env = dict(os.environ, INVESTIGATION_HOME=str(tmp_path / "h"), PYTHONPATH=str(ROOT))
    p = subprocess.run([sys.executable, "-m", "investigation", "analyze", str(FIXTURES), "-o",
                        str(blocker / "out"), "--no-install"], capture_output=True, text=True, env=env, cwd=ROOT)
    assert p.returncode == 2
    assert "Traceback" not in p.stderr


def test_powershell_rule_ignores_encoding_parameter(tmp_path):
    benign = ev(EventID=4104, Channel="Microsoft-Windows-PowerShell/Operational",
                ScriptBlockText="Get-Content C:\\a.txt -Encoding UTF8")
    assert "INV-EVTX-022" not in rule_ids(tmp_path / "a", [benign])
    evil = ev(EventID=4104, Channel="Microsoft-Windows-PowerShell/Operational",
              ScriptBlockText="powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0A")
    assert "INV-EVTX-022" in rule_ids(tmp_path / "b", [evil])


def test_correlation_ignores_undated_events(tmp_path, monkeypatch):
    home = tmp_path / "h"
    (home / "rules").mkdir(parents=True)
    (home / "rules" / "c.yaml").write_text(
        "- id: C-1\n  title: t\n  severity: low\n  mitre: [T1]\n  description: d\n  artifact: services\n"
        "  contains: {name: [x]}\n  correlate: {type: threshold, count: 3, window_seconds: 60, group_by: name}\n")
    monkeypatch.setenv("INVESTIGATION_HOME", str(home))
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    events = [Event(timestamp=T0, timestamp_desc="t", artifact="services", source_file="s", message="m",
                    fields={"name": "x"})]
    events += [Event(timestamp=epoch, timestamp_desc="No Timestamp", artifact="services", source_file="s",
                     message="m", fields={"name": "x"}, tags=("no_timestamp",)) for _ in range(5)]
    store = EventStore(tmp_path / "c.sqlite")
    store.add_many(events)
    assert "C-1" not in {f.rule_id for f in BuiltinRules().detect(store, Context())}


def test_wordwheel_unicode_digit_name_does_not_drop_key():
    from investigation.modules.parsers.registry_extra import _numbered

    assert _numbered({"0": "a", "²": "b", "MRUListEx": b""}) == {0: "a"}
