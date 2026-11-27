import json
import os
from pathlib import Path

import pytest

from investigation.core.module import ModuleMeta, ModuleType, ParserModule
from investigation.core.pipeline import InputError, OutputDirError, analyze
from investigation.core.registry import ModuleRegistry

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "evtx"


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))


def snapshot(root: Path):
    return {p: (p.stat().st_size, p.stat().st_mtime_ns) for p in root.rglob("*")}


def test_analyze_end_to_end(tmp_path):
    before = snapshot(FIXTURES)
    out = tmp_path / "out"
    result = analyze(FIXTURES, out, case_id="2026-001", examiner="analyst", allow_install=False)
    for name in ("report.html", "timeline.csv", "events.jsonl", "findings.json", "investigation.db", "investigation.log"):
        assert (out / name).is_file(), name
    rule_ids = {f["rule_id"] for f in json.loads((out / "findings.json").read_text())["findings"]}
    assert {"INV-EVTX-001", "INV-EVTX-003", "INV-EVTX-004", "INV-EVTX-029a"} <= rule_ids
    assert result.store.count() > 10
    assert result.module_errors == []
    assert "evtx" in result.modules_run and "builtin_rules" in result.modules_run
    assert result.case["case_id"] == "2026-001"
    assert snapshot(FIXTURES) == before


def test_missing_input(tmp_path):
    with pytest.raises(InputError):
        analyze(tmp_path / "nope", tmp_path / "out", allow_install=False)


def test_unsupported_input(tmp_path):
    f = tmp_path / "file.bin"
    f.write_bytes(b"x")
    with pytest.raises(InputError, match="unsupported"):
        analyze(f, tmp_path / "out", allow_install=False)


def test_output_inside_input_rejected(tmp_path):
    src = tmp_path / "evidence"
    src.mkdir()
    with pytest.raises(OutputDirError):
        analyze(src, src / "report", allow_install=False)
    assert not (src / "report").exists()


def test_nonempty_output_requires_force(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "old.txt").write_text("previous report")
    with pytest.raises(OutputDirError):
        analyze(FIXTURES, out, allow_install=False)
    assert (out / "old.txt").read_text() == "previous report"
    analyze(FIXTURES, out, allow_install=False, force=True)
    first = json.loads((out / "findings.json").read_text())
    analyze(FIXTURES, out, allow_install=False, force=True)
    second = json.loads((out / "findings.json").read_text())
    assert len(first["findings"]) == len(second["findings"])


class Crash(ParserModule):
    meta = ModuleMeta(name="crash", description="always fails", type=ModuleType.PARSER)

    def parse(self, source, ctx, errors):
        yield from ()
        raise RuntimeError("parser exploded")


def test_module_crash_is_isolated(tmp_path):
    reg = ModuleRegistry()
    reg.discover(user_dir=None)
    reg.add(Crash)
    out = tmp_path / "out"
    result = analyze(FIXTURES, out, allow_install=False, registry=reg)
    assert any(m == "crash" and "parser exploded" in msg for m, msg in result.module_errors)
    assert (out / "report.html").is_file()
    assert "parser exploded" in (out / "report.html").read_text()
    assert any(f.rule_id == "INV-EVTX-001" for f in result.findings)


def test_store_closed_after_analyze_but_still_readable(tmp_path):
    result = analyze(FIXTURES, tmp_path / "out", allow_install=False)
    assert result.store._db is None
    assert result.store.count() > 10
    result.store.close()
    assert result.store._db is None
