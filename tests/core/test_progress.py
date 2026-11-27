from dataclasses import replace
from datetime import datetime, timezone

import pytest

from investigation.core import console
from investigation.core.collect import collect
from investigation.core.pipeline import analyze
from investigation.core.registry import ModuleRegistry
from investigation.core.requirements import AdminRights, CheckResult, Status
from investigation.modules.collectors import memory, vss
from investigation.modules.collectors.files import OsReader
from investigation.modules.collectors.vss import Shadow
from tests.helpers.windows_tree import build_windows_tree
from tests.modules.test_package_source import AnyFiles, home, make_package
from tests.modules.test_vss_dedupe import AnyVss


@pytest.fixture
def every_update(monkeypatch):
    monkeypatch.setattr(console, "INTERVAL", 0)


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def test_throttle_allows_one_line_per_interval():
    clock = Clock()
    t = console.Throttle(2.0, clock)
    assert t.ready()
    clock.t = 1.9
    assert not t.ready()
    clock.t = 2.0
    assert t.ready()
    assert not t.ready()
    clock.t = 4.5
    assert t.ready()


def test_human_bytes_and_short_path():
    assert console.human_bytes(2_100_000_000) == "2.1 GB"
    assert console.human_bytes(5_000_000) == "5.0 MB"
    assert console.human_bytes(12) == "12 B"
    assert console.short_path("a" * 80, 20) == "..." + "a" * 17
    assert console.short_path("short") == "short"


def _reg():
    reg = ModuleRegistry(fresh=True)
    reg.discover(user_dir=None, entry_points=False)
    reg._modules["files_raw"] = AnyFiles
    reg._modules["vss"] = AnyVss
    return reg


def test_collection_prints_numbered_steps_and_file_counts(tmp_path, monkeypatch, capsys, every_update):
    tree = build_windows_tree(tmp_path / "C")
    monkeypatch.setattr(AdminRights, "check", lambda self, ctx: CheckResult("x", Status.OK, "ok", None, False))
    shadow = Shadow(7, "d7", "C", datetime(2026, 11, 20, tzinfo=timezone.utc), "{a}")
    monkeypatch.setattr(vss, "list_shadows", lambda: [shadow])
    collect(["files_raw", "vss"], out=tmp_path / "pk", registry=_reg(), options={
        "drives": ["C"], "files_readers": {"C": OsReader(tree, None)},
        "vss_readers": {7: ("C", OsReader(tree, None))}})
    out = capsys.readouterr().out
    assert "[1/2] files_raw ..." in out and "[2/2] vss ..." in out
    assert "[files] C: " in out and " files, " in out
    assert "[vss] shadow 1/1 (C:): " in out and "unchanged" in out
    log_text = next((tmp_path / "pk").iterdir()).joinpath("collection.log").read_text(encoding="utf-8")
    assert "[files] C:" not in log_text and "[vss] shadow" not in log_text


def test_no_per_file_flood_when_throttled(tmp_path, monkeypatch, capsys):
    tree = build_windows_tree(tmp_path / "C")
    monkeypatch.setattr(console, "INTERVAL", 10 ** 6)
    collect(["files_raw"], out=tmp_path / "pk", registry=_reg(),
            options={"files_readers": {"C": OsReader(tree, None)}})
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.startswith("[files]")]
    assert len(lines) == 2


def test_analysis_prints_steps_counts_and_report(tmp_path, capsys, every_update):
    pkg = make_package(tmp_path)
    capsys.readouterr()
    analyze(pkg, tmp_path / "o", allow_install=False)
    out = capsys.readouterr().out
    assert " parsing " in out and "] detecting " in out and "writing report ..." in out
    import re

    assert re.search(r"\[1/\d+\] parsing \w+", out)
    assert re.search(r"^  \w+: \d+ events$", out, re.M)


def test_memory_progress_line(tmp_path, monkeypatch, capsys, every_update):
    run = memory.WinPmemRun()
    assert run.feed("max_physical_memory_ 0x480000000\n") is False
    assert run.feed("39% 0x100000000 ....xx..\n") is True
    assert run.percent == 39 and run.expected == 0x480000000 and run.unreadable == 2
