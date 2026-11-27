import json
import shutil
import sqlite3
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from investigation.core.collect import collect
from investigation.core.package import verify_manifest
from investigation.core.pipeline import analyze
from investigation.core.registry import ModuleRegistry
from investigation.core.requirements import AdminRights, CheckResult, Status
from investigation.modules.collectors import vss
from investigation.modules.collectors.files import FilesCollector, OsReader
from investigation.modules.collectors.vss import Shadow, VssCollector
from tests.helpers.windows_tree import build_windows_tree
from tests.modules.test_package_source import AnyFiles, home

SHADOW = Shadow(7, "d7", "C", datetime(2026, 11, 20, 10, 0, tzinfo=timezone.utc), "{abc}")
SYSTEM = "Windows/System32/config/SYSTEM"


class AnyVss(VssCollector):
    meta = replace(VssCollector.meta, platforms=("any",))


def _collect(tmp_path, live_tree, shadow_tree, monkeypatch):
    monkeypatch.setattr(AdminRights, "check", lambda self, ctx: CheckResult("x", Status.OK, "ok", None, False))
    monkeypatch.setattr(vss, "list_shadows", lambda: [SHADOW])
    reg = ModuleRegistry(fresh=True)
    reg.discover(user_dir=None, entry_points=False)
    reg._modules["files_raw"] = AnyFiles
    reg._modules["vss"] = AnyVss
    res = collect(["files_raw", "vss"], out=tmp_path / "pk", registry=reg, options={
        "drives": ["C"], "files_readers": {"C": OsReader(live_tree, None)},
        "vss_readers": {7: ("C", OsReader(shadow_tree, None))}})
    return res.root, {f["path"]: f for f in res.manifest["files"]}


def _same_tree(tmp_path):
    tree = build_windows_tree(tmp_path / "C")
    return tree, tree


def test_unchanged_shadow_files_are_not_stored_again(tmp_path, monkeypatch):
    live, shadow = _same_tree(tmp_path)
    root, files = _collect(tmp_path, live, shadow, monkeypatch)
    key = f"vss/7/C/{SYSTEM}"
    assert not (root / key).exists()
    e = files[key]
    assert e["same_as"] == f"files/C/{SYSTEM}" and e["sha256"] == files[e["same_as"]]["sha256"]
    assert e["size"] == files[e["same_as"]]["size"] and e["shadow_id"] == "{abc}"
    assert not any(p.is_file() for p in (root / "vss" / "7").rglob("*"))
    assert verify_manifest(root, progress=lambda m: None) == []


def test_changed_shadow_file_is_stored(tmp_path, monkeypatch):
    live = build_windows_tree(tmp_path / "C")
    shadow = tmp_path / "S"
    shutil.copytree(live, shadow)
    (shadow / SYSTEM).write_bytes(b"older content")
    root, files = _collect(tmp_path, live, shadow, monkeypatch)
    key = f"vss/7/C/{SYSTEM}"
    assert (root / key).read_bytes() == b"older content" and "same_as" not in files[key]
    other = next(k for k in files if k.startswith("vss/7/") and k != key)
    assert "same_as" in files[other]
    assert verify_manifest(root, progress=lambda m: None) == []


def test_verify_counts_identical_copies_and_fails_closed(tmp_path, monkeypatch):
    live, shadow = _same_tree(tmp_path)
    root, files = _collect(tmp_path, live, shadow, monkeypatch)
    seen = []
    verify_manifest(root, progress=seen.append)
    assert any("identical" in m for m in seen)
    (root / f"files/C/{SYSTEM}").write_bytes(b"tampered")
    assert any("hash mismatch" in p for p in verify_manifest(root, progress=lambda m: None))
    mpath = root / "manifest.json"
    m = json.loads(mpath.read_text())
    for f in m["files"]:
        if f["path"] == f"vss/7/C/{SYSTEM}":
            f["same_as"] = "files/C/does/not/exist"
    mpath.write_text(json.dumps(m))
    assert any("identical-copy entry" in p for p in verify_manifest(root, progress=lambda m: None))


def test_verify_rejects_file_where_entry_is_identical_copy(tmp_path, monkeypatch):
    live, shadow = _same_tree(tmp_path)
    root, _ = _collect(tmp_path, live, shadow, monkeypatch)
    p = root / f"vss/7/C/{SYSTEM}"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"x")
    assert any("identical-copy entry was expected" in x for x in verify_manifest(root, progress=lambda m: None))


def _events(out):
    con = sqlite3.connect(next(Path(out).glob("*.db")))
    try:
        return sorted(con.execute("select artifact from events where source_file like 'vss:%'"))
    finally:
        con.close()


def test_analysis_reads_identical_copies_like_stored_ones(tmp_path, monkeypatch):
    live, shadow = _same_tree(tmp_path)
    root, _ = _collect(tmp_path, live, shadow, monkeypatch)
    analyze(root, tmp_path / "o", allow_install=False)
    got = _events(tmp_path / "o")
    full = tmp_path / "full"
    shutil.copytree(root, full)
    for rel in [p for p in json.loads((root / "manifest.json").read_text())["files"] if "same_as" in p]:
        dest = full / rel["path"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / rel["same_as"], dest)
    from investigation.core.package import write_manifest
    write_manifest(full, {"hostname": "H"})
    analyze(full, tmp_path / "o2", allow_install=False)
    assert got and got == _events(tmp_path / "o2")


def test_analysis_removes_its_temporary_shadow_tree(tmp_path, monkeypatch):
    import tempfile
    live, shadow = _same_tree(tmp_path)
    root, _ = _collect(tmp_path, live, shadow, monkeypatch)
    base = tmp_path / "tmpdir"
    base.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(base))
    from investigation.modules.sources.package import PackageEvidence
    ev = PackageEvidence(root)
    assert ev.sub_sources() and any(base.iterdir())
    ev.close()
    assert not list(base.iterdir())


def _edit_manifest(root, change):
    mpath = root / "manifest.json"
    m = json.loads(mpath.read_text())
    change(m["files"])
    mpath.write_text(json.dumps(m))


def _open(root):
    from investigation.modules.sources.package import PackageEvidence
    return PackageEvidence(root)


def test_traversal_entry_is_rejected(tmp_path, monkeypatch):
    live, shadow = _same_tree(tmp_path)
    root, files = _collect(tmp_path, live, shadow, monkeypatch)
    good = f"vss/7/C/{SYSTEM}"
    evil = "vss/7/C/../../../escape.txt"

    def change(entries):
        e = dict(next(f for f in entries if f["path"] == good))
        e["path"] = evil
        entries.append(e)

    _edit_manifest(root, change)
    ev = _open(root)
    try:
        subs = ev.sub_sources()
        assert not (tmp_path / "escape.txt").exists() and not (root.parent / "escape.txt").exists()
        assert any("invalid identical-copy entry" in m for m in ev.access_errors())
        assert subs and subs[0][0] == "vss:7"
    finally:
        ev.close()


def test_mismatched_same_as_is_rejected(tmp_path, monkeypatch):
    live, shadow = _same_tree(tmp_path)
    root, files = _collect(tmp_path, live, shadow, monkeypatch)
    other = next(p for p, f in files.items() if p.startswith("files/C/") and p != f"files/C/{SYSTEM}")
    other_entry = files[other]

    def change(entries):
        for f in entries:
            if f["path"] == f"vss/7/C/{SYSTEM}":
                f.update(same_as=other, sha256=other_entry["sha256"], size=other_entry["size"])

    _edit_manifest(root, change)
    ev = _open(root)
    try:
        ev.sub_sources()
        assert any("invalid identical-copy entry" in m for m in ev.access_errors())
    finally:
        ev.close()


def test_copy_fallback_is_limited_by_budget(tmp_path, monkeypatch):
    from investigation.modules.sources import package as pkg_mod

    live, shadow = _same_tree(tmp_path)
    root, files = _collect(tmp_path, live, shadow, monkeypatch)
    monkeypatch.setattr(pkg_mod.os, "link", lambda *a, **k: (_ for _ in ()).throw(OSError("no links")))
    sizes = sorted(f["size"] for p, f in files.items() if "same_as" in f)
    monkeypatch.setattr(pkg_mod, "COPY_BUDGET", sizes[0])
    ev = _open(root)
    try:
        ev.sub_sources()
        assert any("not materialised (copy budget)" in n for n in ev.notes)
        n = int(next(n for n in ev.notes if "copy budget" in n).split()[0])
        assert 0 < n < len(sizes)
    finally:
        ev.close()
