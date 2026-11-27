import hashlib
import os
from pathlib import Path

import pytest

from investigation.core.collect import collect
from investigation.core.registry import ModuleRegistry
from investigation.core.requirements import Context
from investigation.modules.collectors import files
from investigation.modules.collectors.files import FilesCollector, OsReader, expand
from tests.helpers.windows_tree import build_windows_tree


def _run(tmp_path, readers, out=None):
    out = out or tmp_path / "out"
    out.mkdir(exist_ok=True)
    extra, warns = {}, []
    ctx = Context(output_dir=out, options={"files_readers": readers, "package_root": out,
                                           "extra_files": extra, "warnings": warns})
    FilesCollector().collect(ctx, out)
    return out, extra, warns


def test_registered_as_files_collector():
    reg = ModuleRegistry(fresh=True)
    reg.discover(user_dir=None, entry_points=False)
    cls = reg.get("files_raw")
    assert cls.meta.category == "files" and cls.meta.priority == 100


def test_expand_case_insensitive_globs(tmp_path):
    tree = build_windows_tree(tmp_path / "C")
    (tree / "Users/IEUser/NTUSER.DAT").write_bytes(b"x")
    assert list(expand(OsReader(tree, None), "Users/*/ntuser.dat")) == ["Users/IEUser/NTUSER.DAT"]


def test_files_collected_in_kape_layout(tmp_path):
    tree = build_windows_tree(tmp_path / "C")
    out, extra, _ = _run(tmp_path, {"C": OsReader(tree, None)})
    rel = "files/C/Windows/System32/config/SYSTEM"
    src = tree / "Windows/System32/config/SYSTEM"
    assert (out / rel).read_bytes() == src.read_bytes()
    assert extra[rel]["source_path"] == "C:\\Windows\\System32\\config\\SYSTEM"
    assert extra[rel]["source_sha256"] == hashlib.sha256(src.read_bytes()).hexdigest()
    assert extra[rel]["source_mtime_utc"]


def test_multiple_drives_each_in_own_folder(tmp_path):
    c = build_windows_tree(tmp_path / "C")
    d = tmp_path / "D"
    (d / "Windows/System32/drivers/etc").mkdir(parents=True)
    (d / "Windows/System32/drivers/etc/hosts").write_text("127.0.0.1 x")
    out, _, _ = _run(tmp_path, {"C": OsReader(c, None), "D": OsReader(d, None)})
    assert (out / "files/C/Windows/System32/config/SYSTEM").is_file()
    assert (out / "files/D/Windows/System32/drivers/etc/hosts").is_file()


def test_raw_only_skipped_with_os_reader(tmp_path, caplog):
    tree = build_windows_tree(tmp_path / "C")
    (tree / "$MFT").write_bytes(b"mft")
    with caplog.at_level("INFO"):
        out, _, _ = _run(tmp_path, {"C": OsReader(tree, None)})
    assert not (out / "files/C/$MFT").exists()
    assert "skipped: needs raw NTFS access" in caplog.text


class Denying(OsReader):
    def open(self, path):
        if path.endswith("SYSTEM"):
            raise PermissionError("locked")
        return super().open(path)


def test_unreadable_file_logged_and_skipped(tmp_path):
    tree = build_windows_tree(tmp_path / "C")
    out, extra, _ = _run(tmp_path, {"C": Denying(tree, None)})
    assert not (out / "files/C/Windows/System32/config/SYSTEM").exists()
    assert "files/C/Windows/System32/config/SYSTEM" not in extra
    assert (out / "files/C/Windows/AppCompat/Programs/Amcache.hve").is_file()


def test_output_dir_inside_root_never_walked(tmp_path):
    tree = build_windows_tree(tmp_path / "C")
    out = tree / "INV_x"
    (out / "files/C/Windows/Prefetch").mkdir(parents=True)
    (out / "files/C/Windows/Prefetch/OLD.pf").write_bytes(b"x")
    (out / "Windows/Prefetch").mkdir(parents=True)
    (out / "Windows/Prefetch/SELF.pf").write_bytes(b"x")
    _run(tmp_path, {"C": OsReader(tree, out)}, out=out)
    assert not (out / "files/C/INV_x").exists()
    assert not (out / "files/C/Windows/Prefetch/SELF.pf").exists()
    assert list(expand(OsReader(tree, out), "*")) .count("INV_x") == 0


def test_os_reader_does_not_follow_symlinks(tmp_path):
    tree = tmp_path / "C"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.pf").write_bytes(b"x")
    (tree / "Windows").mkdir(parents=True)
    try:
        os.symlink(outside, tree / "Windows/Prefetch", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    assert list(expand(OsReader(tree, None), "Windows/Prefetch/*.pf")) == []


def test_ntfs_reader_on_image():
    image = os.environ.get("INVESTIGATION_NTFS_IMAGE")
    if not image:
        pytest.skip("INVESTIGATION_NTFS_IMAGE not set")
    reader = files.NtfsReader(open(image, "rb"))
    assert reader.stat("$MFT")[0] > 0
    assert reader.open("$MFT").read(4) == b"FILE"


def test_collect_merges_collector_warnings(tmp_path, monkeypatch):
    from dataclasses import replace

    class Warn(FilesCollector):
        meta = replace(FilesCollector.meta, platforms=("any",))

        def collect(self, ctx, out_dir):
            ctx.options["warnings"].append("raw NTFS access failed")
    reg = ModuleRegistry(fresh=True)
    reg.discover(user_dir=None, entry_points=False)
    reg._modules["files_raw"] = Warn
    res = collect(["files_raw"], out=tmp_path, registry=reg)
    assert "raw NTFS access failed" in res.manifest["warnings"]


class FakeVolume(OsReader):
    raw = True

    def sparse_prefix(self, path):
        return 4 if path.endswith("hosts") else 0


def test_sparse_prefix_skipped_and_recorded(tmp_path):
    d = tmp_path / "D"
    (d / "Windows/System32/drivers/etc").mkdir(parents=True)
    (d / "Windows/System32/drivers/etc/hosts").write_bytes(b"\0\0\0\0DATA")
    out, extra, _ = _run(tmp_path, {"D": FakeVolume(d)})
    key = "files/D/Windows/System32/drivers/etc/hosts"
    assert (out / key).read_bytes() == b"DATA"
    assert extra[key]["sparse_prefix_bytes"] == 4
    assert extra[key]["source_sha256"] == hashlib.sha256(b"DATA").hexdigest()


def test_ntfs_sparse_prefix_from_dataruns():
    class Rec:
        def dataruns(self, name):
            return [(None, 3), (None, 2), (10, 4), (None, 1)]

        def size(self, name):
            return 100 * 4096

    r = files.NtfsReader.__new__(files.NtfsReader)
    r.exclude = None
    r.ntfs = type("N", (), {"cluster_size": 4096})()
    r._rec = lambda path: (Rec(), "$J")
    assert r.sparse_prefix("x:$J") == 5 * 4096


class StrictRaw:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def seek(self, pos, whence=0):
        self.pos = pos

    def close(self):
        pass

    def read(self, n=-1):
        assert self.pos % 4096 == 0 and n % 4096 == 0, (self.pos, n)
        chunk = self.data[self.pos:self.pos + n]
        self.pos += len(chunk)
        return chunk


def test_aligned_volume_handles_unaligned_reads():
    data = bytes(range(256)) * 100
    vol = files.AlignedVolume(StrictRaw(data), len(data))
    vol.seek(5000)
    assert vol.read(3000) == data[5000:8000]
    vol.seek(len(data) - 7)
    assert vol.read(100) == data[-7:]


class BrokenDir(OsReader):
    def is_dir(self, path):
        if path.endswith("Prefetch"):
            raise RuntimeError("BrokenMftError")
        return super().is_dir(path)


def test_corrupt_entry_does_not_kill_module(tmp_path):
    tree = build_windows_tree(tmp_path / "C")
    out, _, _ = _run(tmp_path, {"C": BrokenDir(tree)})
    assert (out / "files/C/Windows/System32/config/SYSTEM").is_file()


class Failing(OsReader):
    def open(self, path):
        if path.endswith("SYSTEM"):
            class Bad:
                def __enter__(s): return s
                def __exit__(s, *a): pass
                def read(s, n): raise OSError(28, "No space left")
            return Bad()
        return super().open(path)


def test_failed_copy_removes_partial_file(tmp_path):
    tree = build_windows_tree(tmp_path / "C")
    out, extra, _ = _run(tmp_path, {"C": Failing(tree)})
    assert not (out / "files/C/Windows/System32/config/SYSTEM").exists()
    assert "files/C/Windows/System32/config/SYSTEM" not in extra


def test_unknown_drive_warns_and_letters_normalized(tmp_path, monkeypatch):
    monkeypatch.setattr(files, "list_volumes", lambda: [])
    out = tmp_path / "out"
    out.mkdir()
    warns = []
    ctx = Context(output_dir=out, options={"drives": ["z:"], "package_root": out,
                                           "extra_files": {}, "warnings": warns})
    FilesCollector().collect(ctx, out)
    assert warns == ["drive Z not found, skipped"]


def test_chrome_legacy_cookies_target():
    paths = [p for t in files.load_targets() for p in t["paths"]]
    assert "Users/*/AppData/Local/Google/Chrome/User Data/*/Cookies" in paths
