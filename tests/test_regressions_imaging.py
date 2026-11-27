import hashlib
import io
import os
import sys
from pathlib import Path

import pytest

from investigation.core import package as pkg
from investigation.core.collect import collect
from investigation.core.module import CollectorModule, ModuleMeta, ModuleType
from investigation.core.package import verify_manifest, write_manifest
from investigation.core.registry import ModuleRegistry
from investigation.core.requirements import AdminRights, CheckResult, Platform, Status
from investigation.modules.collectors import disk, imaging

ROOT = Path(__file__).resolve().parent.parent
MIB = 1024 * 1024


def test_build_script_checks_interpreter_build_not_cpu():
    text = (ROOT / "packaging" / "build_exe.ps1").read_text()
    assert text.count("win-amd64") >= 2 and "sysconfig.get_platform()" in text
    assert "platform.machine()" not in text.replace("# platform.machine()", "")


def _fake_collect(monkeypatch, calls):
    from investigation import cli as cli_mod
    from investigation.core.collect import CollectResult
    from investigation.modules.collectors.volumes import Volume

    def fake(selection, **kw):
        calls.append((selection, kw))
        return CollectResult(root=Path("pkg"), manifest={"status": "complete", "modules": []}, exit_code=0)

    monkeypatch.setattr(cli_mod, "collect", fake)
    monkeypatch.setattr(cli_mod, "list_volumes", lambda: [Volume("C:", "NTFS", 1, "W", True)])
    return cli_mod


def test_only_memory_tty_asks(monkeypatch, tmp_path):
    calls, asked = [], []
    cli_mod = _fake_collect(monkeypatch, calls)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli_mod, "ask_yes_no", lambda q: asked.append(q) or True)
    assert cli_mod.main(["collect", "--only", "memory", "-o", str(tmp_path)]) == 0
    kw = calls[0][1]
    assert kw["confirm"]("RAM?") is True and asked == ["RAM?"]
    assert kw["declined_detail"] == "declined by examiner"


def test_only_memory_non_tty_not_confirmed(monkeypatch, tmp_path):
    calls = []
    cli_mod = _fake_collect(monkeypatch, calls)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    assert cli_mod.main(["collect", "--only", "memory", "-o", str(tmp_path)]) == 0
    kw = calls[0][1]
    assert kw["confirm"]("x") is False
    assert kw["declined_detail"] == "not confirmed (non-interactive; use --yes)"
    assert cli_mod.main(["collect", "--only", "memory", "--yes", "-o", str(tmp_path)]) == 0
    assert calls[1][1]["confirm"]("x") is True


def test_unconfirmed_module_detail(tmp_path, monkeypatch):
    reg = _disk_reg(monkeypatch, b"x" * MIB)
    res = collect(["disk"], out=tmp_path, registry=reg, confirm=lambda _: False,
                  declined_detail="not confirmed (non-interactive; use --yes)", options={"drives": ["C"]})
    mod = res.manifest["modules"][0]
    assert mod["status"] == "declined" and mod["detail"] == "not confirmed (non-interactive; use --yes)"


def test_all_prompts_happen_before_first_module_runs(tmp_path):
    events = []

    def make(name, prio):
        class C(CollectorModule):
            meta = ModuleMeta(name=name, description=name, type=ModuleType.COLLECTOR, category=name,
                              priority=prio, confirm=f"sure {name}?")

            def collect(self, ctx, out_dir):
                events.append(f"run:{name}")
                return 0

        return C

    reg = ModuleRegistry(fresh=True)
    reg.add(make("a", 1))
    reg.add(make("b", 2))
    collect(["a", "b"], out=tmp_path, registry=reg, confirm=lambda q: events.append(f"ask:{q}") or True)
    assert events == ["ask:sure a?", "ask:sure b?", "run:a", "run:b"]


def _disk_reg(monkeypatch, data):
    ok = lambda self, ctx: CheckResult("x", Status.OK, "ok", None, False)
    monkeypatch.setattr(Platform, "check", ok)
    monkeypatch.setattr(AdminRights, "check", ok)
    monkeypatch.setattr(disk, "physical_disks", lambda: [(0, len(data))])
    monkeypatch.setattr(disk, "disks_of", lambda p: {0})
    monkeypatch.setattr("investigation.modules.collectors.imaging.disks_of", lambda p: {99})
    monkeypatch.setattr(disk, "open_disk", lambda n, size=None: io.BytesIO(data))
    reg = ModuleRegistry(fresh=True)
    reg.discover(user_dir=None, entry_points=False)
    for name in list(reg._modules):
        if name != "disk_image":
            del reg._modules[name]
    return reg


class _Interrupting(io.BytesIO):
    def __init__(self, data, after):
        super().__init__(data)
        self.after = after
        self.reads = 0

    def read(self, n=-1):
        self.reads += 1
        if self.reads > self.after:
            raise KeyboardInterrupt
        return super().read(n)


def test_copy_device_interrupt_truncates_and_attaches_partial(tmp_path):
    data = os.urandom(5 * MIB)
    dest = tmp_path / "x.dd"
    with pytest.raises(KeyboardInterrupt) as ei:
        imaging.copy_device(_Interrupting(data, 2), len(data), dest, chunk=MIB)
    part = ei.value.partial
    assert part.incomplete and part.size == 2 * MIB
    assert dest.read_bytes() == data[:2 * MIB]
    assert part.sha256 == hashlib.sha256(data[:2 * MIB]).hexdigest()


def test_disk_interrupt_records_trusted_hashes(tmp_path, monkeypatch):
    data = os.urandom(5 * MIB)
    reg = _disk_reg(monkeypatch, data)
    monkeypatch.setattr(disk, "open_disk", lambda n, size=None: _Interrupting(data, 2))
    real = disk.copy_device
    monkeypatch.setattr(disk, "copy_device", lambda *a, **k: real(*a, chunk=MIB, **k))
    hashed = []
    real_hash = pkg.hash_file
    monkeypatch.setattr(pkg, "hash_file", lambda p, a=("sha256",): hashed.append(Path(p).name) or real_hash(p, a))
    with pytest.raises(KeyboardInterrupt):
        collect(["disk"], out=tmp_path, registry=reg, confirm=lambda _: True, options={"drives": ["C"]})
    root = next(tmp_path.iterdir())
    import json
    m = json.loads((root / "manifest.json").read_text())
    entry = next(f for f in m["files"] if f["path"] == "disk/PhysicalDrive0.dd")
    assert entry["incomplete"] is True and entry["size"] == 2 * MIB
    assert entry["sha256"] == hashlib.sha256(data[:2 * MIB]).hexdigest()
    assert entry["md5"] == hashlib.md5(data[:2 * MIB]).hexdigest() and entry["sha1"]
    assert "PhysicalDrive0.dd" not in hashed


def test_write_manifest_keyboard_interrupt_leaves_minimal_manifest(tmp_path, monkeypatch):
    (tmp_path / "a.txt").write_text("a")

    def boom(*a, **k):
        raise KeyboardInterrupt

    monkeypatch.setattr(pkg, "hash_file", boom)
    with pytest.raises(KeyboardInterrupt):
        write_manifest(tmp_path, {"status": "aborted"})
    import json
    m = json.loads((tmp_path / "manifest.json").read_text())
    assert m["status"] == "partial" and m["files"] == []


def _package(tmp_path):
    (tmp_path / "disk").mkdir()
    (tmp_path / "memory").mkdir()
    (tmp_path / "disk" / "PhysicalDrive0.dd").write_bytes(b"D" * 100)
    (tmp_path / "memory" / "memory.raw").write_bytes(b"M" * 50)
    extra = {}
    for rel, b in (("disk/PhysicalDrive0.dd", b"D" * 100), ("memory/memory.raw", b"M" * 50)):
        extra[rel] = {"md5": hashlib.md5(b).hexdigest(), "sha256": hashlib.sha256(b).hexdigest(), "size": len(b)}
    write_manifest(tmp_path, {"status": "complete"}, extra)
    return tmp_path


def test_verify_skips_disk_images_by_default(tmp_path):
    root = _package(tmp_path)
    (root / "disk" / "PhysicalDrive0.dd").write_bytes(b"X" * 100)
    assert verify_manifest(root) == [
        "not verified at analysis: disk/PhysicalDrive0.dd (run 'investigation verify <package>')"]
    (root / "memory" / "memory.raw").write_bytes(b"X" * 50)
    assert any("hash mismatch: memory/memory.raw" in p for p in verify_manifest(root))
    assert any("hash mismatch: disk/PhysicalDrive0.dd" in p for p in verify_manifest(root, skip_images=False))


def test_verify_command(tmp_path, capsys):
    from investigation import cli

    root = _package(tmp_path)
    assert cli.main(["verify", str(root)]) == 0
    (root / "disk" / "PhysicalDrive0.dd").write_bytes(b"X" * 100)
    assert cli.main(["verify", str(root)]) == 1
    assert "hash mismatch: disk/PhysicalDrive0.dd" in capsys.readouterr().out


def test_progress_line_for_large_files(tmp_path, monkeypatch):
    root = _package(tmp_path)
    monkeypatch.setattr(pkg, "LARGE_FILE", 60)
    lines = []
    assert verify_manifest(root, skip_images=False, progress=lines.append) == []
    assert len(lines) == 1 and "disk/PhysicalDrive0.dd" in lines[0]


def test_disk_output_on_source_disk_marks_package_partial(tmp_path, monkeypatch):
    reg = _disk_reg(monkeypatch, b"x" * MIB)
    monkeypatch.setattr(disk, "check_target", lambda out, needed, source_disk=None: ["output is on the source disk"])
    res = collect(["disk"], out=tmp_path, registry=reg, confirm=lambda _: True, options={"drives": ["C"]})
    assert res.manifest["modules"][0]["status"] == "ok"
    assert res.manifest["status"] == "partial" and res.exit_code == 1
    assert any("no disk image was produced" in w for w in res.manifest["warnings"])


def test_incomplete_image_marks_package_partial(tmp_path, monkeypatch):
    reg = _disk_reg(monkeypatch, b"x" * MIB)

    def fake(src, size, dest, on_progress=None, **kw):
        dest.write_bytes(b"x")
        return imaging.ImageResult(dest, 1, "m", "s", "h", [], True)

    monkeypatch.setattr(disk, "copy_device", fake)
    res = collect(["disk"], out=tmp_path, registry=reg, confirm=lambda _: True, options={"drives": ["C"]})
    assert res.manifest["status"] == "partial"


def test_good_image_stays_complete(tmp_path, monkeypatch):
    reg = _disk_reg(monkeypatch, b"x" * MIB)
    res = collect(["disk"], out=tmp_path, registry=reg, confirm=lambda _: True, options={"drives": ["C"]})
    assert res.manifest["status"] == "complete"


def test_frozen_forces_no_install(tmp_path, monkeypatch):
    from investigation.core import pipeline

    seen = {}

    def fake_preflight(modules, ctx, installer=None):
        seen["allow"], seen["installer"] = ctx.allow_install, installer
        raise RuntimeError("stop")

    monkeypatch.setattr(pipeline, "is_frozen", lambda: True)
    monkeypatch.setattr(pipeline, "run_preflight", fake_preflight)
    (tmp_path / "in").mkdir()
    with pytest.raises(RuntimeError):
        pipeline.analyze(tmp_path / "in", tmp_path / "out", allow_install=True)
    assert seen == {"allow": False, "installer": None}


def test_unverified_disk_image_is_a_note_not_an_error(tmp_path):
    from investigation.modules.sources.package import PackageEvidence

    root = _package(tmp_path)
    (root / "manifest.json").write_text((root / "manifest.json").read_text().replace(
        '"status": "complete"', '"status": "complete", "format_version": 1'))
    ev = PackageEvidence(root)
    assert ev.access_errors() == []
    assert ev.notes == ["not verified at analysis: disk/PhysicalDrive0.dd (run 'investigation verify <package>')"]
    (root / "memory" / "memory.raw").write_bytes(b"X" * 50)
    assert any("hash mismatch: memory/memory.raw" in e for e in PackageEvidence(root).access_errors())
