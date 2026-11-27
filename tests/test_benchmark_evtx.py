import csv
import importlib.util
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "benchmark_evtx.py"
EVTX = ROOT / "tests" / "fixtures" / "evtx"


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))


@pytest.fixture
def mod():
    spec = importlib.util.spec_from_file_location("benchmark_evtx", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@pytest.fixture
def samples(tmp_path):
    base = tmp_path / "samples"
    (base / "Defense Evasion").mkdir(parents=True)
    (base / "Lateral Movement").mkdir()
    shutil.copy(EVTX / "1102_security_log_cleared.evtx", base / "Defense Evasion")
    shutil.copy(EVTX / "7045_remote_service.evtx", base / "Lateral Movement")
    return base


def test_benchmark_builtin_only(mod, samples, tmp_path, capsys):
    out = tmp_path / "res"
    assert mod.main([str(samples), "-o", str(out), "--builtin-only"]) == 0
    rows = list(csv.DictReader((out / "results.csv").open()))
    assert {r["tactic"] for r in rows} == {"defense_evasion", "lateral_movement"}
    assert all(r["error"] == "" and int(r["events"]) > 0 for r in rows)
    cleared = next(r for r in rows if "1102" in r["file"])
    assert cleared["detected"] == "1" and cleared["matched"] == "1"
    md = (out / "results.md").read_text()
    assert "| Defense Evasion" not in md and "defense_evasion" in md and "TOTAL" in md
    assert "TOTAL" in capsys.readouterr().out


def test_tactic_of(mod, samples):
    f = next((samples / "Lateral Movement").glob("*.evtx"))
    assert mod.tactic_of(f, samples) == "lateral_movement"
    assert mod.tactic_of(samples / "x.evtx", samples) == ""


def test_summarize_rates(mod):
    rows = [
        {"tactic": "execution", "detected": 1, "matched": 0},
        {"tactic": "execution", "detected": 1, "matched": 1},
        {"tactic": "execution", "detected": 0, "matched": 0},
    ]
    assert mod.summarize(rows)[-1] == ("TOTAL", 3, 2, 1)


def test_missing_folder(mod, tmp_path):
    assert mod.main([str(tmp_path / "nope")]) == 2
