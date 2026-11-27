import json
import shutil
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from investigation.core.collect import collect
from investigation.core.package import MANIFEST_NAME, write_manifest
from investigation.core.pipeline import analyze
from investigation.core.registry import ModuleRegistry
from investigation.modules.collectors.files import FilesCollector, OsReader
from investigation.modules.sources import target as target_mod
from investigation.modules.sources.package import PackageEvidence, PackageSource
from investigation.modules.sources import package as package_mod
from tests.helpers.windows_tree import build_windows_tree, open_virtual_target

REAL_OPEN_TARGET = target_mod.open_target


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(target_mod, "open_target", open_virtual_target)


class AnyFiles(FilesCollector):
    meta = replace(FilesCollector.meta, platforms=("any",))


def make_package(tmp_path, tree=None):
    tree = tree or build_windows_tree(tmp_path / "C")
    reg = ModuleRegistry(fresh=True)
    reg.discover(user_dir=None, entry_points=False)
    reg._modules["files_raw"] = AnyFiles
    collect(["files_raw"], out=tmp_path / "pk", registry=reg,
                  options={"files_readers": {"C": OsReader(tree, None)}})
    return next((tmp_path / "pk").iterdir())


def test_package_opened_before_target(tmp_path):
    tree = build_windows_tree(tmp_path / "C")
    pkg = make_package(tmp_path, tree)
    r_pkg = analyze(pkg, tmp_path / "o1", allow_install=False)
    assert r_pkg.modules_run[0] == "investigation_package"
    r_tree = analyze(tree, tmp_path / "o2", allow_install=False)
    for name in ("prefetch", "shimcache"):
        assert name in r_pkg.modules_run
    import sqlite3
    def n(out):
        con = sqlite3.connect(next(Path(out).glob("*.db")))
        try:
            return {r[0]: r[1] for r in con.execute("select artifact, count(*) from events group by 1")}
        finally:
            con.close()
    a, b = n(tmp_path / "o1"), n(tmp_path / "o2")
    assert a.get("prefetch") and a.get("shimcache")
    assert a == b


def test_tampered_file_reported_not_fatal(tmp_path):
    pkg = make_package(tmp_path)
    victim = pkg / "files/C/Windows/System32/config/SYSTEM"
    with open(victim, "ab") as fh:
        fh.write(b"x")
    result = analyze(pkg, tmp_path / "o", allow_install=False)
    assert (tmp_path / "o" / "findings.json").exists()
    assert any("files/C/Windows/System32/config/SYSTEM" in m for _, m in result.module_errors)


def _zip(src: Path, dest: Path, extra=()):
    with zipfile.ZipFile(dest, "w") as z:
        for p in src.rglob("*"):
            if p.is_file():
                z.write(p, p.relative_to(src.parent).as_posix())
        for name, data in extra:
            z.writestr(name, data)


def test_zip_package_opens_and_cleans_up(tmp_path):
    pkg = make_package(tmp_path)
    z = tmp_path / "pkg.zip"
    _zip(pkg, z)
    src = PackageSource()
    assert src.can_open(z)
    ev = src.open(z)
    root = ev.package_root
    assert root.is_dir() and (root / MANIFEST_NAME).is_file()
    assert ev.access_errors() == []
    assert list(ev.glob("windows/prefetch/*.pf"))
    ev.close()
    assert not root.exists()


def test_zip_slip_member_ignored(tmp_path):
    pkg = make_package(tmp_path)
    z = tmp_path / "pkg.zip"
    _zip(pkg, z, [("../evil.txt", b"x"), ("/abs.txt", b"x"), ("C:/drive.txt", b"x")])
    ev = PackageSource().open(z)
    try:
        assert not (tmp_path / "evil.txt").exists()
        assert not (ev.package_root.parent / "evil.txt").exists()
        assert not list(ev.package_root.rglob("evil.txt"))
        assert not list(ev.package_root.rglob("abs.txt"))
        assert not list(ev.package_root.rglob("drive.txt"))
    finally:
        ev.close()


def test_volatile_only_package(tmp_path):
    root = tmp_path / "pk"
    (root / "volatile").mkdir(parents=True)
    (root / "volatile/system_info.csv").write_text(
        "key,value\nhostname,HOST1\nos_caption,Windows 11\nlocal_timezone,UTC\nother,zzz\n", encoding="utf-8")
    write_manifest(root, {})
    ev = PackageSource().open(root)
    assert ev.access_errors() == []
    assert list(ev.iter_files()) == []
    info = ev.system_info()
    assert info["hostname"] == "HOST1" and info["os_caption"] == "Windows 11"
    assert info["local_timezone"] == "UTC" and "other" not in info
    ev.close()


def test_usnjrnl_ads_name_found(tmp_path, monkeypatch):
    from dissect.target.helpers import loaderutil

    root = tmp_path / "pk"
    (root / "files/C/Windows/System32").mkdir(parents=True)
    (root / "files/C/$Extend").mkdir(parents=True)
    (root / "files/C/$Extend/$UsnJrnl%3A$J").write_bytes(b"journal")
    write_manifest(root, {})
    seen = []
    real = loaderutil.add_virtual_ntfs_filesystem

    def spy(target, fs, **kw):
        seen.append(loaderutil._try_open(fs, kw["usnjrnl_path"]) if "usnjrnl_path" in kw else None)
        return real(target, fs, **kw)

    monkeypatch.setattr(loaderutil, "add_virtual_ntfs_filesystem", spy)
    monkeypatch.setattr(target_mod, "open_target", REAL_OPEN_TARGET)
    PackageEvidence(root).close()
    assert seen and seen[0] is not None and seen[0].read() == b"journal"


def _pkg(tmp_path, name="pk"):
    root = tmp_path / name
    (root / "volatile").mkdir(parents=True)
    (root / "volatile/system_info.csv").write_text("key,value\nhostname,H\n", encoding="utf-8")
    write_manifest(root, {})
    return root


def test_symlinked_files_dir_refused(tmp_path):
    outside = build_windows_tree(tmp_path / "outside")
    root = _pkg(tmp_path)
    try:
        (root / "files").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    ev = PackageSource().open(root)
    assert list(ev.iter_files()) == [] and ev.target is None
    assert any("symlink" in m for m in ev.access_errors())
    ev.close()


def test_symlinked_memory_and_csv_ignored(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("key,value\nhostname,STOLEN\n")
    root = _pkg(tmp_path)
    (root / "memory").mkdir()
    (root / "volatile/system_info.csv").unlink()
    try:
        (root / "memory/memory.raw").symlink_to(secret)
        (root / "volatile/system_info.csv").symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    ev = PackageSource().open(root)
    assert ev.memory_image is None
    assert "hostname" not in ev.system_info()
    assert ev.access_errors()
    ev.close()


def test_manifest_traversal_entries_reported_not_read(tmp_path):
    (tmp_path / "x").write_text("host file")
    root = _pkg(tmp_path)
    m = json.loads((root / MANIFEST_NAME).read_text())
    m["files"] += [{"path": "../x", "size": 9, "sha256": "0"}, {"path": "/etc/passwd"}, {"nopath": 1}, "junk"]
    (root / MANIFEST_NAME).write_text(json.dumps(m))
    errs = PackageSource().open(root).access_errors()
    assert sum("unsafe or malformed" in e for e in errs) == 3
    assert not any("hash mismatch" in e for e in errs)


@pytest.mark.parametrize("files", ["nope", {"a": 1}, 5])
def test_malformed_manifest_files_not_fatal(tmp_path, files):
    root = _pkg(tmp_path)
    m = json.loads((root / MANIFEST_NAME).read_text())
    m["files"] = files
    (root / MANIFEST_NAME).write_text(json.dumps(m))
    ev = PackageSource().open(root)
    assert any("malformed" in e for e in ev.access_errors())


def test_manifest_not_a_dict_or_without_version_is_rejected(tmp_path):
    from investigation.core.package import ManifestError

    src = PackageSource()
    d = tmp_path / "a"
    d.mkdir()
    assert not src.can_open(d)
    (d / MANIFEST_NAME).write_text("[1]")
    with pytest.raises(ManifestError):
        src.can_open(d)
    (d / MANIFEST_NAME).write_text('{"files": []}')
    with pytest.raises(ManifestError):
        src.can_open(d)
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("manifest.json", '{"files": []}')
    with pytest.raises(ManifestError):
        src.can_open(z)
    z2 = tmp_path / "b.zip"
    with zipfile.ZipFile(z2, "w") as zf:
        zf.writestr("x.txt", "1")
    assert not src.can_open(z2)
    (tmp_path / "bad.zip").write_bytes(b"not a zip")
    assert not src.can_open(tmp_path / "bad.zip")


def test_target_source_still_opens_plain_kape_dir(tmp_path):
    kape = tmp_path / "kape"
    (kape / "C/Windows/System32").mkdir(parents=True)
    assert target_mod.TargetSource().can_open(kape) and not PackageSource().can_open(kape)


def test_highly_compressible_member_extracts(tmp_path):
    z = tmp_path / "r.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", '{"format_version": 1, "files": []}')
        zf.writestr("big.bin", b"\0" * (5 * 1024 * 1024))
    ev = PackageSource().open(z)
    assert (ev.package_root / "big.bin").stat().st_size == 5 * 1024 * 1024
    ev.close()


def test_zip_declared_total_over_free_space_rejected(tmp_path, monkeypatch):
    import shutil
    from collections import namedtuple
    pkg = _pkg(tmp_path)
    z = tmp_path / "p.zip"
    _zip(pkg, z)
    U = namedtuple("U", "total used free")
    monkeypatch.setattr(shutil, "disk_usage", lambda p: U(10, 10, 1024**3 + 5))
    with pytest.raises(ValueError, match="free space"):
        PackageSource().open(z)


def test_skipped_members_do_not_count_toward_budget(tmp_path, monkeypatch):
    import shutil
    from collections import namedtuple
    pkg = _pkg(tmp_path)
    z = tmp_path / "p.zip"
    _zip(pkg, z, [("pk/../huge.bin", b"a" * 100000), ("__MACOSX/x", b"b" * 100000)])
    real = sum(p.stat().st_size for p in pkg.rglob("*") if p.is_file())
    U = namedtuple("U", "total used free")
    monkeypatch.setattr(shutil, "disk_usage", lambda p: U(10, 10, 1024**3 + real + 10))
    PackageSource().open(z).close()


def test_zip_backslash_names_and_macosx(tmp_path):
    z = tmp_path / "m.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("__MACOSX/._x", "junk")
        zf.writestr("pk\\manifest.json", '{"format_version": 1, "files": []}')
    src = PackageSource()
    assert src.can_open(z)
    ev = src.open(z)
    assert (ev.package_root / MANIFEST_NAME).is_file()
    ev.close()


def test_sds_ads_fallback_mapped(tmp_path, monkeypatch):
    from dissect.target.helpers import loaderutil

    root = tmp_path / "pk"
    (root / "files/C/Windows/System32").mkdir(parents=True)
    (root / "files/C/$Secure%3A$SDS").write_bytes(b"sds")
    (root / "files/C/$Extend").mkdir()
    (root / "files/C/$Extend/$UsnJrnl%3A$J").write_bytes(b"j")
    write_manifest(root, {})
    seen = []
    real = loaderutil.add_virtual_ntfs_filesystem
    monkeypatch.setattr(loaderutil, "add_virtual_ntfs_filesystem",
                        lambda t, fs, **kw: (seen.append(loaderutil._try_open(fs, kw["sds_path"])), real(t, fs, **kw))[1])
    monkeypatch.setattr(target_mod, "open_target", REAL_OPEN_TARGET)
    PackageEvidence(root).close()
    assert seen and seen[0].read() == b"sds"


def test_close_drops_target_before_removing_temp(tmp_path, monkeypatch):
    pkg = make_package(tmp_path)
    z = tmp_path / "pkg.zip"
    _zip(pkg, z)
    ev = PackageSource().open(z)
    root = ev.package_root
    calls = []
    real = shutil.rmtree

    def flaky(path, *a, **k):
        calls.append(path)
        if len(calls) == 1:
            raise PermissionError("in use")
        return real(path)

    monkeypatch.setattr(package_mod.shutil, "rmtree", flaky)
    ev.close()
    assert ev._target is None
    assert len(calls) == 2 and not root.exists()


def test_close_leaves_no_open_files_in_temp(tmp_path):
    import gc
    import io

    pkg = make_package(tmp_path)
    z = tmp_path / "pkg.zip"
    _zip(pkg, z)
    ev = PackageSource().open(z)
    import os

    temp = os.path.realpath(ev.package_root.parent)
    list(ev.glob("windows/prefetch/*.pf"))
    ev.target.registry
    ev.close()
    gc.collect()
    still_open = [o for o in gc.get_objects()
                  if isinstance(o, io.IOBase) and not o.closed
                  and os.path.realpath(str(getattr(o, "name", ""))).startswith(temp)]
    assert still_open == []


def _pad_manifest(pkg, entries=8000):
    m = json.loads((pkg / MANIFEST_NAME).read_text(encoding="utf-8"))
    m["files"] += [{"path": f"vss/9/C/pad/{i:07d}/" + "d/" * 1000 + "x.bin", "size": 0, "sha256": "0" * 64} for i in range(entries)]
    (pkg / MANIFEST_NAME).write_text(json.dumps(m), encoding="utf-8")
    assert (pkg / MANIFEST_NAME).stat().st_size > 16 * 1024 * 1024


def test_manifest_over_16_mib_is_accepted(tmp_path):
    pkg = make_package(tmp_path)
    _pad_manifest(pkg)
    assert PackageSource().can_open(pkg)
    z = tmp_path / "big.zip"
    _zip(pkg, z)
    assert PackageSource().can_open(z)
    result = analyze(pkg, tmp_path / "o", allow_install=False)
    assert result.modules_run[0] == "investigation_package"


def test_invalid_manifest_is_an_input_error(tmp_path):
    from investigation.core.pipeline import InputError

    pkg = make_package(tmp_path)
    (pkg / MANIFEST_NAME).write_text("{not json", encoding="utf-8")
    with pytest.raises(InputError, match="not a valid Investigation manifest"):
        analyze(pkg, tmp_path / "o", allow_install=False)
    (pkg / MANIFEST_NAME).write_text('{"files": []}', encoding="utf-8")
    with pytest.raises(InputError, match="not a valid Investigation manifest"):
        analyze(pkg, tmp_path / "o2", allow_install=False)
    from investigation.cli import main

    assert main(["analyze", str(pkg), "-o", str(tmp_path / "o3")]) == 2


def test_zip_manifest_larger_than_its_header_is_rejected(tmp_path, monkeypatch):
    import io
    from types import SimpleNamespace

    from investigation.core.package import ManifestError, read_zip_manifest

    liar = SimpleNamespace(open=lambda info: io.BytesIO(b"x" * 50))
    with pytest.raises(ManifestError, match="larger than its header says"):
        read_zip_manifest(liar, SimpleNamespace(file_size=10))

    pkg = make_package(tmp_path)
    z = tmp_path / "lie.zip"
    _zip(pkg, z)
    original = zipfile.ZipFile.infolist

    def infolist(self):
        out = original(self)
        for i in out:
            if i.filename.endswith(MANIFEST_NAME):
                i.file_size = 10
        return out

    monkeypatch.setattr(zipfile.ZipFile, "infolist", infolist)
    assert not PackageSource().can_open(z)
