import hashlib
import io
import os
import sys

from investigation.core.collect import collect
from investigation.core.collect_menu import runtime_estimates
from investigation.core.registry import ModuleRegistry
from investigation.core.requirements import AdminRights, CheckResult, Platform, Status
from investigation.modules.collectors import disk

MIB = 1024 * 1024


def _setup(monkeypatch, data):
    ok = lambda self, ctx: CheckResult("x", Status.OK, "ok", None, False)
    monkeypatch.setattr(Platform, "check", ok)
    monkeypatch.setattr(AdminRights, "check", ok)
    monkeypatch.setattr(disk, "physical_disks", lambda: [(0, len(data)), (1, 99)])
    monkeypatch.setattr(disk, "disks_of", lambda p: {0})
    monkeypatch.setattr("investigation.modules.collectors.imaging.disks_of", lambda p: {99})
    monkeypatch.setattr(disk, "open_disk", lambda n, size=None: io.BytesIO(data))
    reg = ModuleRegistry(fresh=True)
    reg.discover(user_dir=None, entry_points=False)
    for name in list(reg._modules):
        if name != "disk_image":
            del reg._modules[name]
    return reg


def test_disk_image_written_and_in_manifest(tmp_path, monkeypatch):
    data = os.urandom(3 * MIB)
    reg = _setup(monkeypatch, data)
    res = collect(["disk"], out=tmp_path, registry=reg, confirm=lambda _: True, options={"drives": ["C"]})
    assert res.manifest["modules"][0]["status"] == "ok"
    img = res.root / "disk" / "PhysicalDrive0.dd"
    assert img.read_bytes() == data
    assert (res.root / "disk" / "PhysicalDrive0.dd.hashes.txt").is_file()
    entry = next(f for f in res.manifest["files"] if f["path"] == "disk/PhysicalDrive0.dd")
    assert entry["md5"] == hashlib.md5(data).hexdigest()
    assert entry["sha1"] == hashlib.sha1(data).hexdigest()
    assert entry["sha256"] == hashlib.sha256(data).hexdigest()
    assert entry["bad_ranges"] == [] and entry["incomplete"] is False
    assert entry["source_path"] == r"\\.\PhysicalDrive0"


def test_disk_image_skipped_when_target_check_fails(tmp_path, monkeypatch):
    reg = _setup(monkeypatch, b"x" * MIB)
    monkeypatch.setattr(disk, "check_target", lambda out, needed, source_disk=None: ["output is on the source disk"])
    res = collect(["disk"], out=tmp_path, registry=reg, confirm=lambda _: True, options={"drives": ["C"]})
    mod = res.manifest["modules"][0]
    assert mod["status"] == "ok" and "source disk" in mod["detail"]
    assert any("source disk" in w for w in res.manifest["warnings"])
    assert not (res.root / "disk" / "PhysicalDrive0.dd").exists()


def test_runtime_estimates_formats_sizes(monkeypatch):
    import psutil
    monkeypatch.setattr("investigation.core.collect_menu.physical_disks", lambda: [(0, 238 * 10**9), (1, 10**9)])
    monkeypatch.setattr("investigation.core.collect_menu.disks_of", lambda p: {0})
    monkeypatch.setattr(psutil, "virtual_memory", lambda: type("M", (), {"total": 16 * 10**9})())
    est = runtime_estimates(["C"])
    assert est["disk"] == "~238 GB" and est["memory"] == "~16 GB"


def _run(tmp_path, reg):
    return collect(["disk"], out=tmp_path, registry=reg, confirm=lambda _: True, options={"drives": ["C"]})


def test_incomplete_and_bad_ranges_reported(tmp_path, monkeypatch):
    from investigation.modules.collectors.imaging import ImageResult
    reg = _setup(monkeypatch, b"x" * MIB)

    def fake(src, size, dest, on_progress=None, **kw):
        dest.write_bytes(b"x" * 10)
        return ImageResult(dest, 10, "m", "s", "h", [(0, 4096), (8192, 4096)], True)

    monkeypatch.setattr(disk, "copy_device", fake)
    res = _run(tmp_path, reg)
    detail = res.manifest["modules"][0]["detail"]
    assert "INCOMPLETE (10 of 1048576 bytes)" in detail and "2 unreadable ranges zero-filled" in detail
    assert any("INCOMPLETE" in w for w in res.manifest["warnings"])


def test_manifest_uses_collector_hash_without_rehash(tmp_path, monkeypatch):
    from investigation.core import package
    data = os.urandom(MIB)
    reg = _setup(monkeypatch, data)
    real = package.hash_file
    seen = []
    monkeypatch.setattr(package, "hash_file", lambda p, *a: seen.append(p.name) or real(p, *a))
    _run(tmp_path, reg)
    assert "PhysicalDrive0.dd" not in seen


def test_interrupted_copy_marks_incomplete(tmp_path, monkeypatch):
    import pytest
    reg = _setup(monkeypatch, b"x" * MIB)

    def boom(src, size, dest, on_progress=None, **kw):
        dest.write_bytes(b"partial")
        raise KeyboardInterrupt

    monkeypatch.setattr(disk, "copy_device", boom)
    with pytest.raises(KeyboardInterrupt):
        _run(tmp_path, reg)
    import json
    pkg = next(tmp_path.iterdir())
    files = {f["path"]: f for f in json.loads((pkg / "manifest.json").read_text())["files"]}
    e = files["disk/PhysicalDrive0.dd"]
    assert e["incomplete"] is True and e["sha256"] and "md5" not in e


def test_disk_honours_image_drives(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(disk, "disks_of", lambda p: seen.append(p) or {0})
    reg = _setup(monkeypatch, b"x" * MIB)
    monkeypatch.setattr(disk, "disks_of", lambda p: seen.append(p) or {0})
    collect(["disk"], out=tmp_path, registry=reg, confirm=lambda _: True,
            options={"drives": ["C"], "image_drives": ["T"]})
    assert seen and all(p.startswith("T:") for p in seen)
