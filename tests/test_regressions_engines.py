"""Regression tests: Volatility isolation, 4688 mapping, IOC scale, YARA edge cases."""
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from investigation.core.models import Event
from investigation.core.requirements import Context
from investigation.core.store import EventStore
from investigation.modules.detections.sigma import SigmaDetection

ROOT = Path(__file__).resolve().parent.parent
SYSMON = "Microsoft-Windows-Sysmon/Operational"
T0 = datetime(2024, 5, 1, tzinfo=timezone.utc)
_n = [0]


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))


def ev(**fields):
    fields.setdefault("Channel", "Security")
    return Event(timestamp=T0, timestamp_desc="t", artifact="evtx", source_file="s", message="m", fields=fields)


def sigma(tmp_path, detection, events, logsource="{product: windows, category: process_creation}"):
    _n[0] += 1
    d = tmp_path / f"rules{_n[0]}"
    d.mkdir()
    (d / "r.yml").write_text(f"title: R\nid: 11111111-2222-3333-4444-{_n[0]:012d}\nlevel: high\n"
                             f"logsource: {logsource}\ndetection:\n{detection}\n")
    store = EventStore(tmp_path / f"db{_n[0]}")
    store.add_many(events)
    ctx = Context(allow_install=False, options={"sigma_paths": [str(d)]})
    return len(list(SigmaDetection().detect(store, ctx, errors=lambda m, s: None)))


def test_volatility_does_not_import_from_cwd(tmp_path, monkeypatch):
    from investigation.modules.parsers import memory as memory_mod
    from investigation.modules.parsers.memory import VolatilityError, VolatilityRunner

    monkeypatch.setattr(memory_mod, "VOL_COMMAND", None)
    planted = tmp_path / "evidence" / "volatility3"
    planted.mkdir(parents=True)
    (planted / "__init__.py").write_text("")
    (planted / "cli.py").write_text("def main():\n    print('{\"PLANTED\": 1}')\n    return 0\n")
    monkeypatch.chdir(tmp_path / "evidence")
    img = tmp_path / "x.mem"
    img.write_bytes(b"\0" * 1024)
    try:
        rows = VolatilityRunner(img, timeout=120).run("windows.pslist")
    except VolatilityError:
        rows = []
    assert {"PLANTED": 1} not in rows


FILTERED = """  sel:
    Image|endswith: '\\\\cmd.exe'
  filter:
    OriginalFileName: Cmd.Exe
  condition: sel and not filter"""


def test_4688_not_used_when_rule_needs_sysmon_only_fields(tmp_path):
    e4688 = ev(EventID=4688, NewProcessName=r"C:\Windows\System32\cmd.exe")
    assert sigma(tmp_path, FILTERED, [e4688]) == 0
    s_ok = ev(EventID=1, Channel=SYSMON, Image=r"C:\Windows\System32\cmd.exe", OriginalFileName="Cmd.Exe")
    s_bad = ev(EventID=1, Channel=SYSMON, Image=r"C:\Users\Public\cmd.exe", OriginalFileName="evil.exe")
    assert sigma(tmp_path, FILTERED, [s_ok]) == 0
    assert sigma(tmp_path, FILTERED, [s_bad]) == 1


def test_4688_integrity_level_and_user_mapping(tmp_path):
    det = """  sel:
    Image|endswith: '\\\\whoami.exe'
  filter:
    IntegrityLevel: System
  condition: sel and not filter"""
    system = ev(EventID=4688, NewProcessName=r"C:\Windows\System32\whoami.exe", MandatoryLabel="S-1-16-16384")
    medium = ev(EventID=4688, NewProcessName=r"C:\Windows\System32\whoami.exe", MandatoryLabel="S-1-16-8192")
    assert sigma(tmp_path, det, [system]) == 0
    assert sigma(tmp_path, det, [medium]) == 1
    det_user = """  sel:
    Image|endswith: '\\\\whoami.exe'
    User|contains: AUTHORI
  condition: sel"""
    e = ev(EventID=4688, NewProcessName=r"C:\Windows\System32\whoami.exe", SubjectUserName="bob",
           SubjectDomainName="CORP", TargetUserName="SYSTEM", TargetDomainName="NT AUTHORITY")
    assert sigma(tmp_path, det_user, [e]) == 1


def test_ioc_scales_with_big_feeds(tmp_path):
    from investigation.modules.detections.ioc import IocMatcher, load_iocs

    feed = tmp_path / "feed.txt"
    feed.write_text("\n".join([f"bad{i}.example.org" for i in range(5000)]
                              + [f"https://host{i}.example.net/p{i}" for i in range(5000)]) + "\n")
    m = IocMatcher(load_iocs([feed]))
    events = [Event(timestamp=T0, timestamp_desc="t", artifact="x", source_file="s",
                    message=f"GET https://site{i}.com/index.html from www.site{i}.com", fields={"url": f"http://a{i}.org/x"})
              for i in range(20000)]
    start = time.monotonic()
    assert all(m.match(e) == [] for e in events)
    assert time.monotonic() - start < 10
    assert ("domain", "bad7.example.org") in m.match(events[0].__class__(
        timestamp=T0, timestamp_desc="t", artifact="x", source_file="s", message="x.bad7.example.org", fields={}))
    hit = Event(timestamp=T0, timestamp_desc="t", artifact="x", source_file="s", message="m",
                fields={"url": "https://host3.example.net/p3?q=1"})
    assert ("url", "https://host3.example.net/p3") in m.match(hit)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs")
def test_yara_skips_fifo(tmp_path):
    from investigation.modules.parsers.yara_scan import YaraScanner
    from investigation.modules.sources.directory import DirectoryEvidence

    d = tmp_path / "ev"
    d.mkdir()
    os.mkfifo(d / "pipe")
    (d / "a.txt").write_text("hello")
    done = []
    t = threading.Thread(target=lambda: done.append(list(YaraScanner().parse(
        DirectoryEvidence(d), Context(), lambda m, s: None))), daemon=True)
    t.start()
    t.join(15)
    assert done, "YARA scan hung on a FIFO"
    assert "pipe" not in list(DirectoryEvidence(d).iter_files())


def test_exited_psscan_process_is_not_hidden(tmp_path, monkeypatch):
    import json

    from investigation.modules.parsers import memory as memory_mod
    from investigation.modules.parsers.memory import MemoryParser
    from investigation.modules.sources.directory import DirectoryEvidence

    vol = tmp_path / "vol"
    vol.mkdir()
    for f in (ROOT / "tests" / "fixtures" / "volatility").iterdir():
        (vol / f.name).write_bytes(f.read_bytes())
    exited = {"PID": 7777, "PPID": 800, "ImageFileName": "conhost.exe", "CreateTime": "2024-05-01T09:00:00+00:00",
              "ExitTime": "2024-05-01T09:00:05+00:00", "__children": []}
    with (vol / "windows.psscan.jsonl").open("a") as fh:
        fh.write(json.dumps(exited) + "\n")
    monkeypatch.setattr(memory_mod, "VOL_COMMAND", [sys.executable, str(vol / "fake_vol.py")])
    img = tmp_path / "m.vmem"
    img.write_bytes(b"\0")
    events = list(MemoryParser().parse(DirectoryEvidence(tmp_path), Context(options={"memory": str(img)}),
                                       lambda m, s: None))
    hidden = [e.fields["PID"] for e in events if "hidden_or_exited" in e.tags]
    assert hidden == [6666]
    assert any(e.fields.get("PID") == 7777 and "exited" in e.tags for e in events)


def test_escaped_wildcard_matches_literal(tmp_path):
    det = """  sel:
    EventID: 4104
    ScriptBlockText: 'a\\*b'
  condition: sel"""
    e = ev(EventID=4104, Channel="Microsoft-Windows-PowerShell/Operational", ScriptBlockText="a*b")
    assert sigma(tmp_path, det, [e], logsource="{product: windows, service: powershell}") == 1


def test_numeric_keyword_matches(tmp_path):
    det = """  keywords:
    - 4688
  condition: keywords"""
    e = ev(EventID=1, Note="saw event 4688 here")
    assert sigma(tmp_path, det, [e], logsource="{product: windows, service: security}") == 1


def test_windash_expansion(tmp_path):
    det = """  sel:
    CommandLine|windash|contains: ' -enc '
  condition: sel"""
    e = ev(EventID=1, Channel=SYSMON, Image=r"C:\x\powershell.exe", CommandLine="powershell /enc AAAA")
    assert sigma(tmp_path, det, [e]) == 1


def test_volatility_oserror_reported(tmp_path):
    from investigation.modules.parsers.memory import VolatilityError, VolatilityRunner

    with pytest.raises(VolatilityError):
        VolatilityRunner(tmp_path / "m", command=[str(tmp_path / "does-not-exist")]).run("windows.pslist")


def test_rules_update_encrypted_member(tmp_path, monkeypatch):
    import zipfile

    from investigation.core.rules_update import update_sigma

    z = tmp_path / "s.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("rules/windows/a.yml", "title: x")

    def boom(self, *a, **k):
        raise RuntimeError("File is encrypted, password required")

    monkeypatch.setattr(zipfile.ZipFile, "read", boom)
    with pytest.raises(ValueError, match="encrypted"):
        update_sigma(zip_path=z)


def _url_ioc_matcher(tmp_path, *iocs):
    from investigation.modules.detections.ioc import IocMatcher, load_iocs

    f = tmp_path / "u.txt"
    f.write_text("\n".join(iocs) + "\n")
    return IocMatcher(load_iocs([f]))


def _e(url):
    return Event(timestamp=T0, timestamp_desc="t", artifact="x", source_file="s", message="m", fields={"url": url})


def test_url_prefix_generation_is_bounded(tmp_path):
    m = _url_ioc_matcher(tmp_path, "https://evil.com/a")
    hostile = "https://x.com/" + "a/" * 200_000
    start = time.monotonic()
    m.match(_e(hostile))
    assert time.monotonic() - start < 2


def test_url_ioc_with_query_matches_longer_query(tmp_path):
    m = _url_ioc_matcher(tmp_path, "https://evil.com/gate.php?id=1")
    assert ("url", "https://evil.com/gate.php?id=1") in m.match(_e("https://evil.com/gate.php?id=1&x=2"))
    assert [h for h in m.match(_e("https://evil.com/gate.php?id=12")) if h[0] == "url"] == []


def test_url_glued_to_text_still_matches(tmp_path):
    m = _url_ioc_matcher(tmp_path, "https://evil.com/p")
    assert ("url", "https://evil.com/p") in m.match(_e("xhttps://evil.com/p/q"))


def test_memory_external_connection_private_filter():
    import re
    import yaml
    from pathlib import Path as _P
    rules = yaml.safe_load(_P("investigation/rules/builtin/memory.yaml").read_text())
    rule = next(r for r in rules if r["id"] == "INV-MEM-004")
    rx = re.compile(rule["not_regex"]["ForeignAddr"][0], re.IGNORECASE | re.ASCII)
    private = ["10.1.2.3", "127.0.0.1", "192.168.1.5", "172.16.0.1", "169.254.1.1", "0.0.0.0", "::", "::1",
               "*", "-", "fe80::1", "fd12:3456::1", "FC00::1", "::ffff:10.0.0.5", "::ffff:127.0.0.1"]
    public = ["8.8.8.8", "172.32.0.1", "::ffff:8.8.8.8", "::2", "2001:db8::1", "fc1::1", "fdx", "0.0.0.01"]
    assert all(rx.search(a) for a in private), [a for a in private if not rx.search(a)]
    assert not any(rx.search(a) for a in public), [a for a in public if rx.search(a)]
