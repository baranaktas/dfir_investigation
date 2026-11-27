import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from investigation.core.rules_update import sigma_rules_present, update_sigma
from investigation.core.requirements import Context, Status

ROOT = Path(__file__).resolve().parent.parent.parent
GOOD = (ROOT / "tests" / "fixtures" / "sigma" / "win_security_audit_log_cleared.yml").read_text()


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    h = tmp_path / "home"
    monkeypatch.setenv("INVESTIGATION_HOME", str(h))
    return h


def make_zip(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return path


def test_update_from_zip(tmp_path, home):
    z = make_zip(tmp_path / "s.zip", {
        "rules/windows/builtin/security/a.yml": GOOD.encode(),
        "rules/windows/process_creation/b.yml": GOOD.replace("c2f690ac", "c2f690ad").encode(),
        "rules/windows/../../../../evil.yml": b"x",
        "/abs/evil.yml": b"x",
        "rules/windows/big.yml": b"#" * (2 * 1024 * 1024),
        "rules/linux/x.yml": b"x",
        "version.txt": b"r2026-07-01",
    })
    stats = update_sigma(zip_path=z)
    assert stats["rules"] == 2
    assert stats["skipped"] >= 3
    target = home / "rules" / "sigma" / "sigmahq"
    assert sorted(p.name for p in target.rglob("*.yml")) == ["a.yml", "b.yml"]
    assert not list(tmp_path.rglob("evil.yml"))
    assert "r2026-07-01" in (target / "VERSION").read_text()
    assert sigma_rules_present()


def test_update_atomic_on_failure(tmp_path, home):
    good = make_zip(tmp_path / "g.zip", {"rules/windows/a.yml": GOOD.encode()})
    update_sigma(zip_path=good)
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"PK\x03\x04 not really a zip")
    with pytest.raises(ValueError):
        update_sigma(zip_path=bad)
    assert (home / "rules" / "sigma" / "sigmahq" / "rules" / "windows" / "a.yml").is_file()


def test_auto_download_when_missing(tmp_path, monkeypatch, caplog):
    from investigation.core.store import EventStore
    from investigation.modules.detections import sigma as sigma_mod

    calls = []

    def fake_update(**kw):
        calls.append(kw)
        return {"rules": 0, "skipped": 0}

    monkeypatch.setattr(sigma_mod, "update_sigma", fake_update)
    store = EventStore(tmp_path / "db")
    errs = []
    list(sigma_mod.SigmaDetection().detect(store, Context(allow_install=True), errors=lambda m, s: errs.append(s)))
    assert len(calls) == 1
    list(sigma_mod.SigmaDetection().detect(store, Context(allow_install=False), errors=lambda m, s: errs.append(s)))
    assert len(calls) == 1
    assert errs == []
    assert "rules update" in caplog.text


def test_cli_rules_update_from_zip(tmp_path, home):
    z = make_zip(tmp_path / "s.zip", {"rules/windows/a.yml": GOOD.encode()})
    env = dict(os.environ, INVESTIGATION_HOME=str(home), PYTHONPATH=str(ROOT))
    p = subprocess.run([sys.executable, "-m", "investigation", "rules", "update", "--from-zip", str(z)],
                       capture_output=True, text=True, env=env, cwd=ROOT)
    assert p.returncode == 0, p.stderr
    assert "1 Sigma rules" in p.stdout
    p = subprocess.run([sys.executable, "-m", "investigation", "rules", "status"],
                       capture_output=True, text=True, env=env, cwd=ROOT)
    assert "sigmahq" in p.stdout and "1" in p.stdout


def test_doctor_warns_without_rules():
    from investigation.modules.detections.sigma import SigmaDetection

    results = [r.check(Context()) for r in SigmaDetection.all_requirements()]
    rules_check = [r for r in results if "Sigma rules" in r.requirement]
    assert rules_check and rules_check[0].status is Status.WARN
    assert "rules update" in rules_check[0].fix
