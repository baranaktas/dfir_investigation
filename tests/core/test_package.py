import json
from datetime import datetime, timezone

from investigation.core.package import hash_file, verify_manifest, write_manifest
from investigation.modules.collectors.base import read_csv, write_csv


def test_write_csv_neutralizes_and_roundtrips(tmp_path):
    p = tmp_path / "sub" / "x.csv"
    dt = datetime(2026, 11, 26, 10, 30, tzinfo=timezone.utc)
    vals = ['=HYPERLINK("x")', "a,b\nc", "İğdır şöğüç", "-1", None, dt]
    cols = [f"c{i}" for i in range(len(vals))]
    n = write_csv(p, cols, [dict(zip(cols, vals))])
    assert n == 1
    raw = p.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    assert "'=HYPERLINK" in raw.decode("utf-8-sig")
    (row,) = list(read_csv(p))
    assert list(row.values()) == ['=HYPERLINK("x")', "a,b\nc", "İğdır şöğüç", "-1", "",
                                  "2026-11-26T10:30:00+00:00"]


def test_write_csv_misc_types(tmp_path):
    p = tmp_path / "x.csv"
    write_csv(p, ["a", "b", "c"], [{"a": True, "b": ["x", "y"]}])
    (row,) = list(read_csv(p))
    assert row == {"a": "true", "b": "x; y", "c": ""}


def test_manifest_hashes_and_verify(tmp_path):
    (tmp_path / "a.txt").write_text("one")
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "b.txt").write_text("two")
    write_manifest(tmp_path, {"status": "complete"}, {"d/b.txt": {"source_path": "C:/b"}})
    m = json.loads((tmp_path / "manifest.json").read_text())
    files = {f["path"]: f for f in m["files"]}
    assert files["a.txt"]["sha256"] == hash_file(tmp_path / "a.txt")["sha256"]
    assert files["d/b.txt"]["source_path"] == "C:/b"
    assert m["status"] == "complete" and m["format_version"] == 1
    assert verify_manifest(tmp_path) == []
    (tmp_path / "a.txt").write_text("changed")
    assert any("a.txt" in p for p in verify_manifest(tmp_path))
    (tmp_path / "new.txt").write_text("x")
    assert any("not in manifest" in p and "new.txt" in p for p in verify_manifest(tmp_path))


def test_verify_manifest_ignores_unicode_normalization(tmp_path):
    import unicodedata

    from investigation.core.package import verify_manifest, write_manifest

    nfc = unicodedata.normalize("NFC", "İndirilenler.lnk")
    (tmp_path / nfc).write_bytes(b"lnk")
    write_manifest(tmp_path, {"status": "complete"})
    nfd = unicodedata.normalize("NFD", nfc)
    (tmp_path / nfc).rename(tmp_path / (nfd + ".tmp"))
    (tmp_path / (nfd + ".tmp")).rename(tmp_path / nfd)
    assert verify_manifest(tmp_path) == []


def test_manifest_trusts_matching_size_and_sha256(tmp_path, monkeypatch):
    from investigation.core import package
    (tmp_path / "a.bin").write_bytes(b"abc")
    (tmp_path / "b.bin").write_bytes(b"abc")
    calls = []
    real = package.hash_file
    monkeypatch.setattr(package, "hash_file", lambda p, *a: calls.append(p.name) or real(p, *a))
    path = write_manifest(tmp_path, {}, {"a.bin": {"sha256": "T", "size": 3, "md5": "m"},
                                         "b.bin": {"sha256": "T", "size": 99}})
    files = {f["path"]: f for f in json.loads(path.read_text())["files"]}
    assert files["a.bin"]["sha256"] == "T" and files["a.bin"]["md5"] == "m"
    assert files["b.bin"]["sha256"] == real(tmp_path / "b.bin")["sha256"] and files["b.bin"]["size"] == 3
    assert "a.bin" not in calls and "b.bin" in calls
