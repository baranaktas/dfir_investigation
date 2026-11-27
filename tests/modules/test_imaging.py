import errno
import hashlib
import io
import os
from pathlib import Path

import pytest

from investigation.core.package import write_manifest
from investigation.modules.collectors import imaging
from investigation.modules.collectors.imaging import ImageResult, check_target, copy_device, write_hash_file

MIB = 1024 * 1024
GIB = 1024 * MIB


def test_copy_device_hashes_match(tmp_path):
    data = os.urandom(10 * MIB)
    dest = tmp_path / "d.raw"
    res = copy_device(io.BytesIO(data), len(data), dest, chunk=MIB)
    assert res.md5 == hashlib.md5(data).hexdigest()
    assert res.sha1 == hashlib.sha1(data).hexdigest()
    assert res.sha256 == hashlib.sha256(data).hexdigest()
    assert dest.read_bytes() == data
    assert res.size == len(data) and res.bad_ranges == [] and not res.incomplete


class BadSrc(io.BytesIO):
    def __init__(self, data, bad_chunk_start, bad_sector):
        super().__init__(data)
        self.cs, self.bs = bad_chunk_start, bad_sector

    def read(self, n=-1):
        pos = self.tell()
        if n > 512 and pos == self.cs:
            raise OSError(23, "crc")
        if n == 512 and pos == self.bs:
            raise OSError(23, "crc")
        return super().read(n)


def test_bad_sector_zero_filled(tmp_path):
    data = os.urandom(4 * MIB)
    bad = MIB + 1024
    src = BadSrc(data, MIB, bad)
    dest = tmp_path / "d.raw"
    res = copy_device(src, len(data), dest, chunk=MIB, sector=512)
    out = dest.read_bytes()
    assert len(out) == len(data)
    assert out[bad:bad + 512] == bytes(512)
    assert out[:bad] == data[:bad] and out[bad + 512:] == data[bad + 512:]
    assert res.bad_ranges == [(bad, 512)]


def test_adjacent_bad_sectors_merge(tmp_path):
    class S(BadSrc):
        def read(self, n=-1):
            if n == 512 and self.tell() in (1024, 1536):
                raise OSError(23, "crc")
            return super().read(n)
    data = os.urandom(2 * MIB)
    res = copy_device(S(data, 0, -1), len(data), tmp_path / "d.raw", chunk=MIB, sector=512)
    assert res.bad_ranges == [(1024, 1024)]


def test_disk_full_marks_incomplete(tmp_path, monkeypatch):
    dest = tmp_path / "d.raw"
    real_open = open
    class W:
        def __init__(self, f): self.f, self.n = f, 0
        def write(self, b):
            self.n += 1
            if self.n == 3:
                raise OSError(errno.ENOSPC, "full")
            return self.f.write(b)
        def truncate(self, n): self.f.truncate(n)
        def close(self): self.f.close()
        def __enter__(self): return self
        def __exit__(self, *a): self.close()
    monkeypatch.setattr(imaging, "_open_dest", lambda p: W(real_open(p, "wb")))
    data = os.urandom(5 * MIB)
    res = copy_device(io.BytesIO(data), len(data), dest, chunk=MIB)
    assert res.incomplete is True
    assert dest.exists() and dest.stat().st_size == 2 * MIB
    assert res.md5 == hashlib.md5(data[:2 * MIB]).hexdigest()


def test_keyboard_interrupt_closes_and_reraises(tmp_path):
    class S(io.BytesIO):
        def read(self, n=-1):
            raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        copy_device(S(b"x" * 10), 10, tmp_path / "d.raw")


def test_check_target_free_space_fat32_same_disk(tmp_path, monkeypatch):
    U = type("U", (), {})
    def usage(free):
        u = U(); u.free = free; return u
    monkeypatch.setattr(imaging.shutil, "disk_usage", lambda p: usage(10 * GIB))
    monkeypatch.setattr(imaging, "volume_fstype", lambda p: "NTFS")
    monkeypatch.setattr(imaging, "disks_of", lambda p: {1})
    assert check_target(tmp_path, 5 * GIB, source_disk=0) == []
    monkeypatch.setattr(imaging.shutil, "disk_usage", lambda p: usage(5 * GIB))
    free = check_target(tmp_path, 5 * GIB)
    assert len(free) == 1
    monkeypatch.setattr(imaging.shutil, "disk_usage", lambda p: usage(100 * GIB))
    monkeypatch.setattr(imaging, "volume_fstype", lambda p: "FAT32")
    fat = check_target(tmp_path, 5 * GIB)
    assert len(fat) == 1 and fat != free
    assert check_target(tmp_path, 4 * GIB - 1) == []
    monkeypatch.setattr(imaging, "volume_fstype", lambda p: "NTFS")
    same = check_target(tmp_path, GIB, source_disk=1)
    assert len(same) == 1 and same != free and same != fat


def test_refuses_image_of_output_disk(tmp_path, monkeypatch):
    monkeypatch.setattr(imaging, "disks_of", lambda p: {2, 3})
    monkeypatch.setattr(imaging, "volume_fstype", lambda p: "NTFS")
    assert check_target(tmp_path, 1, source_disk=3)
    assert not check_target(tmp_path, 1, source_disk=4)


def test_hash_file_format(tmp_path):
    r = ImageResult(tmp_path / "a.raw", 7, "m", "s1", "s2", [(0, 512)], False)
    p = write_hash_file(r)
    assert p == tmp_path / "a.raw.hashes.txt"
    assert p.read_text() == "md5  m\nsha1  s1\nsha256  s2\nsize  7\nbad_ranges  1\n"


def test_manifest_keeps_extra_hash_fields(tmp_path):
    (tmp_path / "a.raw").write_bytes(b"abc")
    write_manifest(tmp_path, {}, {"a.raw": {"md5": "m", "sha1": "s"}})
    import json
    f = json.loads((tmp_path / "manifest.json").read_text())["files"]
    e = [x for x in f if x["path"] == "a.raw"][0]
    assert e["md5"] == "m" and e["sha1"] == "s" and "sha256" in e


class HalfWriter:
    """Writes half of the 3rd chunk, then fails with ENOSPC."""
    def __init__(self, path, close_fails=False, fail=True):
        self.f = open(path, "wb", buffering=0)
        self.n, self.close_fails, self.fail = 0, close_fails, fail

    def write(self, b):
        self.n += 1
        if self.fail and self.n == 3:
            self.f.write(bytes(b[:len(b) // 2]))
            raise OSError(errno.ENOSPC, "full")
        return self.f.write(b)

    def truncate(self, n):
        self.f.truncate(n)

    def close(self):
        self.f.close()
        if self.close_fails:
            raise OSError(errno.ENOSPC, "flush")


def test_partial_write_truncated_to_hashed_bytes(tmp_path, monkeypatch):
    dest = tmp_path / "d.raw"
    monkeypatch.setattr(imaging, "_open_dest", lambda p: HalfWriter(p))
    data = os.urandom(5 * MIB)
    res = copy_device(io.BytesIO(data), len(data), dest, chunk=MIB)
    assert res.incomplete and res.size == 2 * MIB == dest.stat().st_size
    assert hashlib.sha256(dest.read_bytes()).hexdigest() == res.sha256


def test_close_failure_marks_incomplete(tmp_path, monkeypatch):
    monkeypatch.setattr(imaging, "_open_dest", lambda p: HalfWriter(p, close_fails=True, fail=False))
    data = os.urandom(MIB)
    res = copy_device(io.BytesIO(data), len(data), tmp_path / "d.raw", chunk=MIB)
    assert res.incomplete is True and res.sha256 == hashlib.sha256(data).hexdigest()


def test_default_sector_is_4096():
    import inspect
    assert inspect.signature(copy_device).parameters["sector"].default == 4096


def test_partial_sector_read_zero_padded_and_recorded(tmp_path):
    class S(io.BytesIO):
        def read(self, n=-1):
            if n == 4096 and self.tell() == 4096:
                return super().read(100)
            if n > 4096 and self.tell() == 0:
                raise OSError(23, "crc")
            return super().read(n)
    data = os.urandom(MIB)
    dest = tmp_path / "d.raw"
    res = copy_device(S(data), len(data), dest, chunk=MIB)
    out = dest.read_bytes()
    assert out[4096:4196] == data[4096:4196] and out[4196:8192] == bytes(4096 - 100)
    assert res.bad_ranges == [(4096, 4096)]


def _patch_target(monkeypatch, disks):
    class U: free = 100 * GIB
    monkeypatch.setattr(imaging.shutil, "disk_usage", lambda p: U)
    monkeypatch.setattr(imaging, "volume_fstype", lambda p: "NTFS")
    monkeypatch.setattr(imaging, "disks_of", lambda p: disks)


def test_unknown_disk_refuses_local_output(tmp_path, monkeypatch):
    _patch_target(monkeypatch, None)
    msgs = check_target(tmp_path, 1, source_disk=0)
    assert len(msgs) == 1 and "cannot determine" in msgs[0]
    assert check_target(tmp_path, 1) == []


def test_unc_output_skips_same_disk_check(monkeypatch):
    _patch_target(monkeypatch, None)
    monkeypatch.setattr(Path, "mkdir", lambda *a, **k: None)
    assert check_target(Path("\\\\server\\share\\out"), 1, source_disk=0) == []


def test_check_target_creates_out_dir(tmp_path, monkeypatch):
    _patch_target(monkeypatch, {1})
    d = tmp_path / "a" / "b"
    check_target(d, 1)
    assert d.is_dir()


def test_volume_root_handles_unc_and_drive():
    from investigation.modules.collectors.volumes import _volume_root
    assert _volume_root("\\\\srv\\sh\\x\\y") == "\\\\srv\\sh\\"
