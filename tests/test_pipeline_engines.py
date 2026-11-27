import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from investigation.core.pipeline import analyze
from investigation.modules.parsers import memory as memory_mod

ROOT = Path(__file__).resolve().parent.parent
FAKE = [sys.executable, str(ROOT / "tests" / "fixtures" / "volatility" / "fake_vol.py")]


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


def test_end_to_end_all_engines(tmp_path, monkeypatch):
    monkeypatch.setattr(memory_mod, "VOL_COMMAND", FAKE)
    ev = tmp_path / "evidence"
    ev.mkdir()
    for f in (ROOT / "tests" / "fixtures" / "evtx").glob("*.evtx"):
        (ev / f.name).write_bytes(f.read_bytes())
    (ev / "shell.php").write_bytes(b"<?php eval(base64_decode($_POST['x'])); system($_GET['c']); ?>")
    ioc = tmp_path / "iocs.txt"
    ioc.write_text("PC01.example.corp\n")
    mem = tmp_path / "mem.vmem"
    mem.write_bytes(b"\0" * 16)
    out = tmp_path / "out"
    analyze(ev, out, allow_install=False, options={
        "sigma_paths": [str(ROOT / "tests" / "fixtures" / "sigma")], "ioc_files": [str(ioc)], "memory": str(mem)})
    rules = [f["rule_id"] for f in json.loads((out / "findings.json").read_text())["findings"]]
    for prefix in ("SIGMA-", "YARA-", "IOC-", "INV-MEM-", "INV-EVTX-"):
        assert any(r.startswith(prefix) for r in rules), (prefix, rules)
    assert "Sigma: 4 rules loaded" in (out / "report.html").read_text()


def test_doctor_lists_engine_requirements(home):
    env = dict(os.environ, INVESTIGATION_HOME=str(home), PYTHONPATH=str(ROOT))
    p = subprocess.run([sys.executable, "-m", "investigation", "doctor"], capture_output=True, text=True, env=env,
                       cwd=ROOT)
    for text in ("pysigma", "yara-python", "volatility3", "Sigma rules (SigmaHQ)"):
        assert text in p.stdout, text
    assert "rules update" in p.stdout or "bundled SigmaHQ" in p.stdout


def test_memory_profile_resolves():
    from investigation.core.profiles import load_profile, resolve
    from investigation.core.registry import ModuleRegistry

    reg = ModuleRegistry()
    reg.discover(user_dir=None)
    names = [m.meta.name for m in resolve(load_profile("memory"), reg)]
    assert "memory" in names and "process_tree" in names and "evtx" not in names
