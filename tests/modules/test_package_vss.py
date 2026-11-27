import shutil
import sys
import sqlite3
from pathlib import Path

import pytest

from investigation.core.models import Event
from investigation.core.module import ModuleMeta, ModuleType, ParserModule
from investigation.core.package import write_manifest
from investigation.core.pipeline import analyze
from investigation.core.registry import ModuleRegistry
from investigation.modules.parsers import memory as memory_mod
from investigation.modules.sources import target as target_mod
from investigation.modules.parsers.dissect_adapter import ArtifactSpec
from investigation.modules.sources.package import PackageEvidence
from tests.modules.test_package_source import home, make_package

ROOT = Path(__file__).resolve().parent.parent.parent
FAKE = [sys.executable, str(ROOT / "tests" / "fixtures" / "volatility" / "fake_vol.py")]


def add_vss(pkg, n=3):
    shutil.copytree(pkg / "files" / "C", pkg / "vss" / str(n) / "C")
    write_manifest(pkg, {"hostname": "H"})


def rows(out, sql):
    con = sqlite3.connect(next(Path(out).glob("*.db")))
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def test_vss_tree_parsed_with_prefix(tmp_path):
    pkg = make_package(tmp_path)
    add_vss(pkg)
    analyze(pkg, tmp_path / "o", allow_install=False)
    got = rows(tmp_path / "o", "select source_file, tags from events where artifact='prefetch'")
    vss = [r for r in got if r[0].startswith("vss:3:")]
    plain = [r for r in got if not r[0].startswith("vss:")]
    assert vss and plain and len(vss) == len(plain)
    assert all("vss" in r[1] for r in vss) and not any("vss" in r[1] for r in plain)


def test_heavy_parsers_skip_vss(tmp_path):
    calls = []

    class FakeHeavy(ParserModule):
        meta = ModuleMeta(name="fakeheavy", description="x", type=ModuleType.PARSER)
        spec = ArtifactSpec(name="fakeheavy", artifact="fakeheavy", function="x", evidence_type="execution", description="x", heavy=True)

        def parse(self, source, ctx, errors):
            calls.append(source)
            return iter(())

    pkg = make_package(tmp_path)
    add_vss(pkg)
    reg = ModuleRegistry(fresh=True)
    reg.discover(user_dir=None, entry_points=False)
    reg._modules["fakeheavy"] = FakeHeavy
    analyze(pkg, tmp_path / "o", allow_install=False, registry=reg)
    assert len(calls) == 1


def test_broken_shadow_reported_not_fatal(tmp_path, monkeypatch):
    pkg = make_package(tmp_path)
    add_vss(pkg)
    real = target_mod.open_target

    def flaky(path, *a, **k):
        if "vss" in Path(path).parts:
            raise RuntimeError("boom")
        return real(path, *a, **k)

    monkeypatch.setattr(target_mod, "open_target", flaky)
    result = analyze(pkg, tmp_path / "o", allow_install=False)
    assert any("vss/3" in m for _, m in result.module_errors)
    assert rows(tmp_path / "o", "select count(*) from events where artifact='prefetch'")[0][0] > 0


def test_package_memory_image_goes_to_memory_parser(tmp_path, monkeypatch):
    monkeypatch.setattr(memory_mod, "VOL_COMMAND", FAKE)
    pkg = make_package(tmp_path)
    (pkg / "memory").mkdir()
    (pkg / "memory" / "memory.raw").write_bytes(b"\0" * 4096)
    write_manifest(pkg, {"hostname": "H"})
    result = analyze(pkg, tmp_path / "o", allow_install=False)
    assert result.store.artifact_counts().get("memory_process", 0) >= 6


def test_odd_vss_entries_not_opened(tmp_path):
    pkg = make_package(tmp_path)
    (pkg / "vss").mkdir()
    (pkg / "vss" / "3").write_text("file")
    (pkg / "vss" / "x").mkdir()
    shutil.copytree(pkg / "files" / "C", pkg / "vss" / "03" / "C")
    outside = tmp_path / "outside"
    shutil.copytree(pkg / "files" / "C", outside / "C")
    try:
        (pkg / "vss" / "4").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    ev = PackageEvidence(pkg)
    try:
        assert ev.sub_sources() == []
        assert any("symlink" in m and "vss/4" in m for m in ev.access_errors())
    finally:
        ev.close()


def test_uncontained_package_opens_no_shadows(tmp_path, monkeypatch):
    pkg = make_package(tmp_path)
    add_vss(pkg)
    def refuse(p):
        raise ValueError("symlink escapes package")
    monkeypatch.setattr(target_mod, "check_directory_containment", refuse)
    opened = []
    monkeypatch.setattr(target_mod, "open_target", lambda *a, **k: opened.append(a))
    ev = PackageEvidence(pkg)
    assert ev.sub_sources() == [] and opened == []
    ev.close()


def test_escaping_symlink_inside_shadow_skipped(tmp_path, monkeypatch):
    pkg = make_package(tmp_path)
    add_vss(pkg, 3)
    add_vss(pkg, 4)
    ev = PackageEvidence(pkg)
    real = target_mod.check_directory_containment

    def check(p):
        if Path(p).name == "3":
            raise ValueError("symlink escapes package")
        return real(p)

    monkeypatch.setattr(target_mod, "check_directory_containment", check)
    try:
        assert [p for p, _ in ev.sub_sources()] == ["vss:4"]
        assert any("vss/3" in m for m in ev.access_errors())
    finally:
        ev.close()
