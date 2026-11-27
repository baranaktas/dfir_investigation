import hashlib
import json
import sys
import zipfile
from pathlib import Path

import pytest

from investigation.core import archive
from investigation.core.archive import ZipSkipped, sidecar_for, zip_package
from investigation.core.collect import CollectResult
from investigation.core.package import verify_zip, write_manifest
from investigation.modules.sources.package import PackageSource


def _package(tmp_path):
    root = tmp_path / "INV_H_20260101T000000Z"
    (root / "files" / "C").mkdir(parents=True)
    (root / "files/C/a.bin").write_bytes(b"A" * 3000)
    (root / "memory").mkdir()
    (root / "memory/memory.raw").write_bytes(b"R" * 5000)
    (root / "collection.log").write_text("log")
    extra = {"vss/7/C/a.bin": {"same_as": "files/C/a.bin", "sha256": hashlib.sha256(b"A" * 3000).hexdigest()}}
    write_manifest(root, {"hostname": "H", "status": "complete"}, extra)
    return root


def test_zip_contains_package_and_hash_file(tmp_path):
    root = _package(tmp_path)
    lines = []
    zip_path, side = zip_package(root, lines.append)
    assert zip_path == tmp_path / (root.name + ".zip") and side == sidecar_for(zip_path)
    with zipfile.ZipFile(zip_path) as z:
        names = set(z.namelist())
        assert f"{root.name}/manifest.json" in names and f"{root.name}/memory/memory.raw" in names
        assert z.read(f"{root.name}/manifest.json") == (root / "manifest.json").read_bytes()
        assert z.getinfo(f"{root.name}/memory/memory.raw").compress_type == zipfile.ZIP_DEFLATED
    assert side.read_text().split()[0] == hashlib.sha256(zip_path.read_bytes()).hexdigest()
    assert root.is_dir()
    assert any(ln.startswith("[zip] 100% (") for ln in lines)


def test_zip_progress_is_throttled(tmp_path, monkeypatch):
    from investigation.core import console

    monkeypatch.setattr(console, "INTERVAL", 10 ** 6)
    monkeypatch.setattr(archive, "CHUNK", 1000)
    lines = []
    zip_package(_package(tmp_path), lines.append)
    assert len(lines) == 2


def test_zip_skipped_without_free_space(tmp_path, monkeypatch):
    root = _package(tmp_path)
    monkeypatch.setattr(archive.shutil, "disk_usage", lambda p: type("U", (), {"free": 10})())
    with pytest.raises(ZipSkipped, match="not enough free space"):
        zip_package(root, lambda m: None)
    assert not (tmp_path / (root.name + ".zip")).exists()


def test_partial_zip_removed_on_failure(tmp_path, monkeypatch):
    root = _package(tmp_path)
    monkeypatch.setattr(archive, "CHUNK", 100)
    calls = []

    def boom(msg):
        calls.append(msg)
        raise KeyboardInterrupt

    from investigation.core import console

    monkeypatch.setattr(console, "INTERVAL", 0)
    with pytest.raises(KeyboardInterrupt):
        zip_package(root, boom)
    assert not (tmp_path / (root.name + ".zip")).exists()


def test_verify_zip_accepts_and_detects_changes(tmp_path):
    root = _package(tmp_path)
    zip_path, _ = zip_package(root, lambda m: None)
    seen = []
    assert verify_zip(zip_path, seen.append) == [] and any("identical" in m for m in seen)
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(zip_path) as src, zipfile.ZipFile(bad, "w") as dst:
        for i in src.infolist():
            data = src.read(i)
            if i.filename.endswith("a.bin"):
                data = b"B" * len(data)
            dst.writestr(i.filename, data)
        dst.writestr(f"{root.name}/extra.txt", "x")
    problems = verify_zip(bad, lambda m: None)
    assert any("hash mismatch: files/C/a.bin" in p for p in problems)
    assert any("not in manifest: extra.txt" in p for p in problems)


def test_analyzer_accepts_the_zip(tmp_path):
    root = _package(tmp_path)
    zip_path, _ = zip_package(root, lambda m: None)
    assert PackageSource().can_open(zip_path)


def _cli(monkeypatch, tmp_path):
    from tests.test_cli import _fake_collect

    root = _package(tmp_path)
    cli_mod = _fake_collect(monkeypatch, [])
    monkeypatch.setattr(cli_mod, "collect",
                        lambda selection, **kw: CollectResult(root=root, manifest={"status": "complete", "modules": []},
                                                              exit_code=0))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    return cli_mod, root


def test_zip_flag_creates_zip(monkeypatch, tmp_path, capsys):
    cli_mod, root = _cli(monkeypatch, tmp_path)
    assert cli_mod.main(["collect", "--zip"]) == 0
    out = capsys.readouterr().out
    assert (tmp_path / (root.name + ".zip")).is_file() and root.is_dir()
    assert "You can delete the folder after checking the zip with: investigation verify" in out
    assert cli_mod.main(["verify", str(tmp_path / (root.name + ".zip"))]) == 0


def test_no_zip_without_flag_when_not_interactive(monkeypatch, tmp_path):
    cli_mod, root = _cli(monkeypatch, tmp_path)
    cli_mod.main(["collect"])
    assert not (tmp_path / (root.name + ".zip")).exists()


def test_interactive_question_answers(monkeypatch, tmp_path, capsys):
    cli_mod, root = _cli(monkeypatch, tmp_path)
    asked = []
    monkeypatch.setattr(cli_mod, "ask_yes_no", lambda q, *a, **k: asked.append(q) or False)
    cli_mod._offer_zip(root, False, True)
    assert asked == ["Compress the package into a zip?"] and not (tmp_path / (root.name + ".zip")).exists()
    monkeypatch.setattr(cli_mod, "ask_yes_no", lambda q, *a, **k: True)
    cli_mod._offer_zip(root, False, True)
    assert (tmp_path / (root.name + ".zip")).is_file()


def test_zip_offered_after_interrupt(monkeypatch, tmp_path):
    cli_mod, root = _cli(monkeypatch, tmp_path)

    def stop(selection, **kw):
        exc = KeyboardInterrupt()
        exc.package_root = root
        raise exc

    monkeypatch.setattr(cli_mod, "collect", stop)
    assert cli_mod.main(["collect", "--zip"]) == 130
    assert (tmp_path / (root.name + ".zip")).is_file()


def test_verify_detects_zip_hash_file_mismatch(monkeypatch, tmp_path, capsys):
    cli_mod, root = _cli(monkeypatch, tmp_path)
    zip_path, side = zip_package(root, lambda m: None)
    side.write_text("0" * 64 + "  x.zip\n")
    assert cli_mod.main(["verify", str(zip_path)]) == 1
    assert "does not match" in capsys.readouterr().out
