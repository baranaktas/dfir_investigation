from pathlib import Path

from investigation.modules.sources.directory import DirectorySource


def test_directory_glob_case_insensitive(tmp_path):
    logs = tmp_path / "Windows" / "System32" / "winevt" / "Logs"
    logs.mkdir(parents=True)
    (logs / "Security.EVTX").write_bytes(b"x")
    (tmp_path / "top.evtx").write_bytes(b"y")
    (tmp_path / "note.txt").write_text("z")
    mod = DirectorySource()
    assert mod.can_open(tmp_path)
    assert not mod.can_open(tmp_path / "note.txt")
    with mod.open(tmp_path) as src:
        assert sorted(src.glob("**/*.evtx")) == ["Windows/System32/winevt/Logs/Security.EVTX", "top.evtx"]
        assert list(src.glob("*.evtx")) == ["top.evtx"]
        assert list(src.glob("windows/system32/winevt/logs/*.evtx")) == ["Windows/System32/winevt/Logs/Security.EVTX"]


def test_directory_open_is_read_only(tmp_path):
    (tmp_path / "a.bin").write_bytes(b"abc")
    with DirectorySource().open(tmp_path) as src:
        with src.open("a.bin") as fh:
            assert fh.mode == "rb"
            assert fh.read() == b"abc"


def test_directory_open_rejects_escape(tmp_path):
    import pytest

    (tmp_path / "inner").mkdir()
    with DirectorySource().open(tmp_path / "inner") as src:
        with pytest.raises(ValueError):
            src.open("../secret")
