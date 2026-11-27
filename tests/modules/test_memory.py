import json
import os
import sys
from pathlib import Path

import pytest

from investigation.core.requirements import Context
from investigation.modules.parsers import memory as memory_mod
from investigation.modules.parsers.memory import MemoryParser, VolatilityError, VolatilityRunner
from investigation.modules.sources.directory import DirectoryEvidence

ROOT = Path(__file__).resolve().parent.parent.parent
FAKE = [sys.executable, str(ROOT / "tests" / "fixtures" / "volatility" / "fake_vol.py")]
EVTX = ROOT / "tests" / "fixtures" / "evtx"


@pytest.fixture(autouse=True)
def fake_vol(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(memory_mod, "VOL_COMMAND", FAKE)


@pytest.fixture
def image(tmp_path):
    p = tmp_path / "mem.vmem"
    p.write_bytes(b"\0" * 4096)
    return p


def run(image, **opts):
    errors = []
    events = list(MemoryParser().parse(DirectoryEvidence(image.parent), Context(options={"memory": str(image), **opts}),
                                       lambda m, s: errors.append(s)))
    return events, errors


def test_events_per_plugin(image):
    events, errors = run(image)
    arts = {}
    for e in events:
        arts.setdefault(e.artifact, []).append(e)
    assert len([e for e in arts["memory_process"] if "hidden_or_exited" not in e.tags]) == 6
    assert any("-enc" in e.message for e in arts["memory_cmdline"])
    assert arts["memory_malfind"][0].fields["Protection"] == "PAGE_EXECUTE_READWRITE"
    assert arts["memory_service"][0].fields["Binary"].endswith("upd.exe")
    assert any("netscan" in e for e in errors)
    lsass = next(e for e in arts["memory_process"] if e.fields["ImageFileName"] == "lsass.exe")
    assert lsass.timestamp.isoformat() == "2024-05-01T08:00:06+00:00" and lsass.timestamp_desc == "Process Created"
    mal = arts["memory_malfind"][0]
    assert mal.timestamp.isoformat() == "2024-05-01T12:30:00+00:00" and mal.timestamp_desc == "Memory Captured"


def test_hidden_process_tagged(image):
    events, _ = run(image)
    hidden = [e for e in events if "hidden_or_exited" in e.tags]
    assert [e.fields["PID"] for e in hidden] == [6666]


def test_children_flattened():
    rows = VolatilityRunner(Path("x"), command=FAKE).run("windows.pslist")
    assert [r["PID"] for r in rows] == [4, 300, 500, 600, 700, 800]
    assert all("__children" not in r for r in rows)


def test_timeout_reported(image, monkeypatch):
    monkeypatch.setenv("FAKE_VOL_SLEEP", "3")
    with pytest.raises(VolatilityError, match="timed out"):
        VolatilityRunner(image, timeout=1, command=FAKE).run("windows.pslist")


def test_bad_json_reported(tmp_path):
    bad = tmp_path / "bad_vol.py"
    bad.write_text("print('{not json')\n")
    with pytest.raises(VolatilityError, match="JSON"):
        VolatilityRunner(Path("x"), command=[sys.executable, str(bad)]).run("windows.pslist")


def test_no_memory_does_nothing(tmp_path):
    assert list(MemoryParser().parse(DirectoryEvidence(tmp_path), Context(), lambda m, s: None)) == []


def test_cli_memory_flag(image, tmp_path, monkeypatch):
    from investigation.core.pipeline import analyze

    result = analyze(EVTX, tmp_path / "out", allow_install=False, options={"memory": str(image)})
    assert result.store.artifact_counts().get("memory_process", 0) >= 6
    assert result.store.artifact_counts().get("evtx", 0) > 0


def test_memory_only_input(image, tmp_path):
    from investigation.core.pipeline import analyze

    result = analyze(image, tmp_path / "out", allow_install=False)
    assert result.modules_run[0] == "memory_image"
    assert result.store.artifact_counts().get("memory_process", 0) >= 6


def test_cli_parses_memory_option():
    from investigation.cli import build_parser

    args = build_parser().parse_args(["analyze", "x", "--memory", "m.raw"])
    assert args.memory == "m.raw"


def test_console_history_recovered_from_cmdscan_and_consoles(image):
    events, errors = run(image)
    consoles = [e for e in events if e.artifact == "memory_console"]
    assert sorted(e.message for e in consoles) == [
        "conhost.exe pid=4120: net user backdoor P@ss1 /add",
        "conhost.exe pid=4120: vssadmin delete shadows /all /quiet",
        "conhost.exe pid=4120: whoami /all",
    ]
    assert all(e.evidence_type.value == "execution" for e in consoles)
    assert not any("cmdscan" in e or "consoles" in e for e in errors)
