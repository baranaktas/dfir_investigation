import json
from pathlib import Path

import pytest

from investigation.core.module import ModuleMeta, ModuleType, SourceModule
from investigation.core.pipeline import analyze
from investigation.core.registry import ModuleRegistry
from investigation.modules.sources.directory import DirectoryEvidence

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "evtx"


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))


class InfoEvidence(DirectoryEvidence):
    def system_info(self):
        return {"hostname": "PC1", "os": "windows"}


def _source(name, priority, evidence=DirectoryEvidence):
    cls = type(name, (SourceModule,), {
        "can_open": lambda self, p: True,
        "open": lambda self, p: evidence(p),
    })
    cls.meta = ModuleMeta(name=name, description="", type=ModuleType.SOURCE, priority=priority)
    return cls


def _registry(*sources):
    reg = ModuleRegistry()
    reg.discover(user_dir=None)
    for s in sources:
        reg.add(s)
    return reg


def test_lower_priority_source_wins(tmp_path):
    reg = _registry(_source("aaa_late", 500), _source("zzz_early", 5))
    result = analyze(FIXTURES, tmp_path / "out", allow_install=False, registry=reg)
    assert result.modules_run[0] == "zzz_early"


def test_system_info_in_case(tmp_path):
    reg = _registry(_source("info_src", 1, InfoEvidence))
    analyze(FIXTURES, tmp_path / "out", allow_install=False, registry=reg)
    data = json.loads((tmp_path / "out" / "findings.json").read_text())
    assert data["case"]["system"]["hostname"] == "PC1"
    assert "PC1" in (tmp_path / "out" / "report.html").read_text()


def test_default_source_has_no_system_info():
    assert DirectoryEvidence(FIXTURES).system_info() == {}
    assert DirectoryEvidence(FIXTURES).is_system is False
