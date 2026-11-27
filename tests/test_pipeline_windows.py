import json

import pytest

from investigation.core.pipeline import analyze
from investigation.core.profiles import load_profile, resolve
from investigation.core.registry import ModuleRegistry
from investigation.modules.sources import target as target_mod
from tests.helpers.windows_tree import build_windows_tree, open_virtual_target


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))


def test_windows_tree_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setattr(target_mod, "open_target", open_virtual_target)
    tree = build_windows_tree(tmp_path / "C")
    before = {p: (p.stat().st_size, p.stat().st_mtime_ns) for p in tree.rglob("*")}
    out = tmp_path / "out"
    result = analyze(tree, out, allow_install=False, case_id="WIN-1")
    assert {"target", "prefetch", "shimcache", "evtx", "builtin_rules"} <= set(result.modules_run)
    counts = result.store.artifact_counts()
    assert {"prefetch", "shimcache", "evtx", "amcache", "lnk", "services"} <= set(counts)
    data = json.loads((out / "findings.json").read_text())
    assert data["case"]["system"]["hostname"] == "DESKTOP-M3OSHQU"
    html = (out / "report.html").read_text()
    assert "Interpretation notes" in html
    assert "Shimcache does not prove execution" in html
    assert (out / "stories.json").is_file()
    assert [m for m, _ in result.module_errors if not m.startswith("load:")] == []
    assert {p: (p.stat().st_size, p.stat().st_mtime_ns) for p in tree.rglob("*")} == before


def _resolved(name):
    reg = ModuleRegistry()
    reg.discover(user_dir=None)
    return [m.meta.name for m in resolve(load_profile(name), reg)]


def test_triage_profile_excludes_heavy():
    names = _resolved("triage")
    assert "prefetch" in names and "evtx" in names
    assert not {"mft", "usnjrnl", "thumbcache", "defender_mplog"} & set(names)


@pytest.mark.parametrize("profile", ["ransomware", "lateral-movement"])
def test_new_profiles_resolve(profile):
    names = _resolved(profile)
    assert "target" in names and "builtin_rules" in names and "html_report" in names


def test_small_e01_runs_without_events(tmp_path):
    from tests.helpers.windows_tree import FIXTURES

    result = analyze(FIXTURES / "small.E01", tmp_path / "out", allow_install=False)
    assert result.modules_run[0] == "target"
    assert (tmp_path / "out" / "report.html").is_file()
