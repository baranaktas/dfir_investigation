import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from investigation.core.models import Event
from investigation.core.requirements import Context
from investigation.core.store import EventStore
from investigation.modules.detections.ioc import IocDetection, IocMatcher, load_iocs

ROOT = Path(__file__).resolve().parent.parent.parent
T0 = datetime(2024, 5, 1, tzinfo=timezone.utc)
SHA1 = "8e01cdeb9a1c23cee421a647f29c45f67623be97"


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


def ev(msg="m", **fields):
    return Event(timestamp=T0, timestamp_desc="t", artifact="x", source_file="s", message=msg, fields=fields)


@pytest.fixture
def ioc_file(tmp_path):
    f = tmp_path / "iocs.txt"
    f.write_text(f"""# campaign X
{SHA1}
d41d8cd98f00b204e9800998ecf8427e
185.220.101.5
hxxps://evil[.]com/payload.exe
bad-domain(.)net

2001:db8::dead
dropper_v2.exe
not an ioc with spaces
""")
    return f


def test_parse_and_defang(ioc_file):
    s = load_iocs([ioc_file])
    assert s.hashes == {SHA1, "d41d8cd98f00b204e9800998ecf8427e"}
    assert s.ips == {"185.220.101.5", "2001:db8::dead"}
    assert s.urls == {"https://evil.com/payload.exe"}
    assert s.domains == {"evil.com", "bad-domain.net"}
    assert s.filenames == {"dropper_v2.exe"}
    assert s.count == 8


def test_match_types(ioc_file):
    m = IocMatcher(load_iocs([ioc_file]))
    assert ("hash", SHA1) in m.match(ev(digest_sha1=SHA1.upper()))
    assert ("ip", "185.220.101.5") in m.match(ev(IpAddress="185.220.101.5"))
    assert ("ip", "185.220.101.5") in m.match(ev("conn to 185.220.101.5:443"))
    assert ("domain", "evil.com") in m.match(ev(url="http://sub.evil.com/a"))
    assert m.match(ev(url="http://notevil.com/a")) == []
    assert ("url", "https://evil.com/payload.exe") in m.match(ev(url="https://evil.com/payload.exe?x=1"))
    assert ("filename", "dropper_v2.exe") in m.match(ev(path=r"C:\Users\Public\Dropper_V2.exe"))
    assert m.match(ev(path=r"C:\x\my_dropper_v2.exe")) == []
    assert m.match(ev("185.220.101.50 is different")) == []


def test_detection_and_no_iocs(ioc_file, tmp_path):
    store = EventStore(tmp_path / "db")
    store.add_many([ev(IpAddress="185.220.101.5"), ev(IpAddress="185.220.101.5"), ev(path=r"c:\dropper_v2.exe")])
    findings = list(IocDetection().detect(store, Context(options={"ioc_files": [str(ioc_file)]})))
    by = {f.title: f for f in findings}
    assert len(by["IOC match: 185.220.101.5"].events) == 2
    assert "IOC match: dropper_v2.exe" in by
    assert list(IocDetection().detect(store, Context())) == []


def test_home_ioc_dir(home, tmp_path):
    (home / "ioc").mkdir(parents=True)
    (home / "ioc" / "feed.txt").write_text("185.220.101.5\n")
    store = EventStore(tmp_path / "db")
    store.add_many([ev(IpAddress="185.220.101.5")])
    assert [f.title for f in IocDetection().detect(store, Context())] == ["IOC match: 185.220.101.5"]


def test_cli_ioc_flag(tmp_path, home):
    f = tmp_path / "i.txt"
    f.write_text("PC01.example.corp\n")
    out = tmp_path / "out"
    env = dict(os.environ, INVESTIGATION_HOME=str(home), PYTHONPATH=str(ROOT))
    p = subprocess.run([sys.executable, "-m", "investigation", "analyze", str(ROOT / "tests/fixtures/evtx"), "-o",
                        str(out), "--no-install", "--ioc", str(f)], capture_output=True, text=True, env=env, cwd=ROOT)
    assert p.returncode == 0, p.stderr
    rules = [x["rule_id"] for x in json.loads((out / "findings.json").read_text())["findings"]]
    assert any(r.startswith("IOC-domain") for r in rules)
