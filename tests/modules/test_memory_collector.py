import hashlib
import subprocess
import threading
from pathlib import Path

from investigation.core.collect import collect
from investigation.core.registry import ModuleRegistry
from investigation.core.requirements import AdminRights, CheckResult, Platform, Status
from investigation.modules.collectors import memory


restricted = []
events = []


def _setup(monkeypatch, tmp_path):
    restricted.clear()
    events.clear()
    ok = lambda self, ctx: CheckResult("x", Status.OK, "ok", None, False)
    monkeypatch.setattr(Platform, "check", ok)
    monkeypatch.setattr(AdminRights, "check", ok)
    fake = tmp_path / "winpmem.exe"
    fake.write_bytes(b"fake")
    monkeypatch.setattr(memory, "WINPMEM_SHA256", hashlib.sha256(b"fake").hexdigest())
    monkeypatch.setattr(memory, "_load_winpmem", lambda: b"fake")
    monkeypatch.setattr(memory, "winpmem_path", lambda: fake)
    monkeypatch.setattr(memory, "_search_dirs", lambda: [tmp_path / "resdir"])
    def make_dir():
        d = tmp_path / ("inv-winpmem-" + "ab" * 16)
        d.mkdir()
        restricted.append(d)
        return d

    monkeypatch.setattr(memory, "_create_private_dir", make_dir)
    monkeypatch.setattr(memory, "_open_deny_write", lambda p: events.append("open") or p)
    monkeypatch.setattr(memory, "_sha256_of_handle", lambda h: events.append("hash") or memory.WINPMEM_SHA256)
    monkeypatch.setattr(memory, "_close_handle", lambda h: events.append("close"))
    monkeypatch.setattr(memory.platform, "machine", lambda: "AMD64")
    monkeypatch.setattr(memory.psutil, "virtual_memory", lambda: type("M", (), {"total": 1000})())
    monkeypatch.setattr(memory, "check_target", lambda out, needed, source_disk=None: [])
    reg = ModuleRegistry(fresh=True)
    reg.discover(user_dir=None, entry_points=False)
    for name in list(reg._modules):
        if name != "memory_winpmem":
            del reg._modules[name]
    return reg, fake


class FakePopen:
    """Stands in for subprocess.Popen: prints `lines`, writes `data` to the target file, exits with `code`."""

    def __init__(self, argv, lines, code, data, kw):
        self.argv, self.kw, self.code, self.killed = argv, kw, code, False
        self.returncode = None
        self._lines, self._data = lines, data
        self.stdout = self._gen()

    def _gen(self):
        events.append("run")
        if self._data is not None:
            Path(self.argv[1]).write_bytes(self._data)
        for ln in self._lines:
            if self.killed:
                return
            yield ln

    def wait(self, timeout=None):
        self.returncode = -9 if self.killed else self.code
        return self.returncode

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True


def _popen(monkeypatch, lines=(), code=0, data=b"RAMDATA", launch_error=None):
    made = []

    def make(argv, **kw):
        if launch_error:
            events.append("run")
            raise launch_error
        p = FakePopen(argv, lines, code, data, kw)
        made.append(p)
        return p

    monkeypatch.setattr(memory.subprocess, "Popen", make)
    return made


class ImmediateTimer:
    """A timer that fires as soon as it starts; records the interval it was given."""

    last = None

    def __init__(self, interval, fn):
        self.interval, self.fn, self.daemon = interval, fn, False
        ImmediateTimer.last = self

    def start(self):
        self.fn()

    def cancel(self):
        pass


def _run(tmp_path, reg):
    return collect(["memory"], out=tmp_path / "out", registry=reg, confirm=lambda _: True)


def test_winpmem_path_rejects_wrong_hash(tmp_path, monkeypatch):
    (tmp_path / "winpmem").mkdir()
    (tmp_path / "winpmem" / memory.WINPMEM_NAME).write_bytes(b"not winpmem")
    monkeypatch.setattr(memory, "_search_dirs", lambda: [tmp_path / "winpmem"])
    assert memory.winpmem_path() is None
    (tmp_path / "winpmem" / memory.WINPMEM_NAME).unlink()
    assert memory.winpmem_path() is None


def test_memory_runs_embedded_winpmem(tmp_path, monkeypatch):
    reg, fake = _setup(monkeypatch, tmp_path)
    made = _popen(monkeypatch, lines=["driver ok\n"])
    res = _run(tmp_path, reg)
    assert res.manifest["modules"][0]["status"] == "ok"
    exe = Path(made[0].argv[0])
    assert exe != fake and not exe.exists() and not made[0].kw.get("shell")
    assert exe.parent.name.startswith("inv-winpmem-") and exe.parent == restricted[0]
    assert events == ["open", "hash", "run", "close"]
    assert not exe.parent.exists()
    entry = next(f for f in res.manifest["files"] if f["path"] == "memory/memory.raw")
    assert entry["md5"] == hashlib.md5(b"RAMDATA").hexdigest()
    assert entry["sha1"] == hashlib.sha1(b"RAMDATA").hexdigest()
    assert entry["sha256"] == hashlib.sha256(b"RAMDATA").hexdigest()
    assert entry["tool"] == memory.WINPMEM_NAME and entry["tool_sha256"] == memory.WINPMEM_SHA256
    assert "unreadable_pages" not in entry and "winpmem_exit" not in entry
    assert any("driver was loaded" in w for w in res.manifest["warnings"])


def test_memory_timeout_value(tmp_path, monkeypatch):
    reg, _ = _setup(monkeypatch, tmp_path)
    _popen(monkeypatch)
    monkeypatch.setattr(memory.threading, "Timer", ImmediateTimer)
    _run(tmp_path, reg)
    assert ImmediateTimer.last.interval >= 3600


def test_memory_nonzero_exit_is_error(tmp_path, monkeypatch):
    reg, _ = _setup(monkeypatch, tmp_path)
    _popen(monkeypatch, lines=["driver load failed XYZ\n"], code=1, data=None)
    res = _run(tmp_path, reg)
    mod = res.manifest["modules"][0]
    assert mod["status"] == "error" and "driver load failed XYZ" in mod["detail"]
    assert "exit 1" in mod["detail"]


def test_memory_failure_without_output_is_not_blank(tmp_path, monkeypatch):
    reg, _ = _setup(monkeypatch, tmp_path)
    _popen(monkeypatch, lines=[], code=3, data=None)
    mod = _run(tmp_path, reg).manifest["modules"][0]
    assert mod["status"] == "error" and mod["detail"].strip().endswith("no output from WinPmem")


def test_memory_failure_message_is_limited(tmp_path, monkeypatch):
    reg, _ = _setup(monkeypatch, tmp_path)
    _popen(monkeypatch, lines=[f"line {i} " + "z" * 80 + "\n" for i in range(30)], code=1, data=None)
    mod = _run(tmp_path, reg).manifest["modules"][0]
    assert "line 29" in mod["detail"] and "line 0 " not in mod["detail"] and len(mod["detail"]) < 700


def _complete_run_lines():
    return ["max_physical_memory_ 0x7d0\n",
            "22% 0x100000000 ....xxxx....\n",
            "100% 0x7d0 ..x.....\n",
            "Driver Unloaded.\n"]


def test_exit_one_with_complete_image_is_ok(tmp_path, monkeypatch):
    reg, _ = _setup(monkeypatch, tmp_path)
    _popen(monkeypatch, lines=_complete_run_lines(), code=1, data=b"A" * 2000)
    res = _run(tmp_path, reg)
    mod = res.manifest["modules"][0]
    assert mod["status"] == "ok"
    assert mod["detail"].endswith("5 unreadable pages") and "GiB" in mod["detail"] and "exit" not in mod["detail"]
    entry = next(f for f in res.manifest["files"] if f["path"] == "memory/memory.raw")
    assert entry["unreadable_pages"] == 5 and entry["winpmem_exit"] == 1
    assert entry["sha256"] == hashlib.sha256(b"A" * 2000).hexdigest() and "incomplete" not in entry


def test_failure_exit_codes_are_errors_even_with_a_full_image(tmp_path, monkeypatch):
    for code in (-1, 4294967295, 2):
        (tmp_path / str(code)).mkdir()
        reg, _ = _setup(monkeypatch, tmp_path / str(code))
        _popen(monkeypatch, lines=_complete_run_lines(), code=code, data=b"A" * 2000)
        mod = _run(tmp_path / str(code), reg).manifest["modules"][0]
        assert mod["status"] == "error", code


def test_nonzero_exit_with_short_image_is_error(tmp_path, monkeypatch):
    reg, _ = _setup(monkeypatch, tmp_path)
    _popen(monkeypatch, lines=_complete_run_lines(), code=1, data=b"A" * 1999)
    res = _run(tmp_path, reg)
    assert res.manifest["modules"][0]["status"] == "error"
    entry = next(f for f in res.manifest["files"] if f["path"] == "memory/memory.raw")
    assert entry["incomplete"] is True


def test_nonzero_exit_without_expected_size_is_error(tmp_path, monkeypatch):
    reg, _ = _setup(monkeypatch, tmp_path)
    _popen(monkeypatch, lines=["22% 0x1 ....\n"], code=1, data=b"A" * 5000)
    assert _run(tmp_path, reg).manifest["modules"][0]["status"] == "error"


def test_zero_exit_reports_unreadable_pages(tmp_path, monkeypatch):
    reg, _ = _setup(monkeypatch, tmp_path)
    _popen(monkeypatch, lines=["50% 0x10 xx..\n"], code=0)
    res = _run(tmp_path, reg)
    mod = res.manifest["modules"][0]
    assert mod["status"] == "ok" and "2 unreadable pages" in mod["detail"] and "exit" not in mod["detail"]


def test_winpmem_lines_are_logged(tmp_path, monkeypatch):
    reg, _ = _setup(monkeypatch, tmp_path)
    _popen(monkeypatch, lines=["hello from winpmem\n"])
    res = _run(tmp_path, reg)
    log_text = (Path(res.root) / "collection.log").read_text(encoding="utf-8")
    assert "winpmem: hello from winpmem" in log_text


def test_memory_skipped_on_arm64(tmp_path, monkeypatch):
    reg, _ = _setup(monkeypatch, tmp_path)
    monkeypatch.setattr(memory.platform, "machine", lambda: "ARM64")
    res = _run(tmp_path, reg)
    mod = res.manifest["modules"][0]
    assert mod["status"] == "skipped" and "ARM64" in mod["detail"]


def test_memory_target_check_blocks(tmp_path, monkeypatch):
    reg, _ = _setup(monkeypatch, tmp_path)
    monkeypatch.setattr(memory, "check_target", lambda out, needed, source_disk=None: ["not enough free space"])

    def boom(*a, **k):
        raise AssertionError("must not run")

    monkeypatch.setattr(memory.subprocess, "Popen", boom)
    res = _run(tmp_path, reg)
    mod = res.manifest["modules"][0]
    assert mod["status"] == "error" and "not enough free space" in mod["detail"]


def test_rehash_mismatch_does_not_run_and_cleans_up(tmp_path, monkeypatch):
    reg, _ = _setup(monkeypatch, tmp_path)
    seen = []
    monkeypatch.setattr(memory, "_sha256_of_handle", lambda h: seen.append(h) or "0" * 64)

    def boom(*a, **k):
        raise AssertionError("must not run")

    monkeypatch.setattr(memory.subprocess, "Popen", boom)
    res = _run(tmp_path, reg)
    assert res.manifest["modules"][0]["status"] == "error"
    assert seen and not seen[0].parent.exists() and events[-1] == "close"


def test_private_dir_removed_after_failure(tmp_path, monkeypatch):
    reg, _ = _setup(monkeypatch, tmp_path)
    made = _popen(monkeypatch, lines=["bad\n"], code=1, data=None)
    _run(tmp_path, reg)
    assert made and not Path(made[0].argv[0]).parent.exists()


def test_timeout_is_error_and_warning_recorded(tmp_path, monkeypatch):
    reg, _ = _setup(monkeypatch, tmp_path)
    made = _popen(monkeypatch, lines=["x\n"] * 3, data=b"partial")
    monkeypatch.setattr(memory.threading, "Timer", ImmediateTimer)
    res = _run(tmp_path, reg)
    mod = res.manifest["modules"][0]
    assert mod["status"] == "error" and "timed out after 3600 s" in mod["detail"]
    assert made[0].killed
    assert any("driver was loaded" in w for w in res.manifest["warnings"])
    entry = next(f for f in res.manifest["files"] if f["path"] == "memory/memory.raw")
    assert entry["incomplete"] is True and entry["tool"] == memory.WINPMEM_NAME


def test_winpmem_path_ok_with_right_hash(tmp_path, monkeypatch):
    d = tmp_path / "w"
    d.mkdir()
    (d / memory.WINPMEM_NAME).write_bytes(b"x")
    monkeypatch.setattr(memory, "WINPMEM_SHA256", hashlib.sha256(b"x").hexdigest())
    monkeypatch.setattr(memory, "_search_dirs", lambda: [d])
    assert memory.winpmem_path() == d / memory.WINPMEM_NAME and memory._load_winpmem() == b"x"


def test_private_dir_creation_failure_runs_nothing(tmp_path, monkeypatch):
    reg, _ = _setup(monkeypatch, tmp_path)

    def fail():
        raise RuntimeError("cannot create the private WinPmem directory: already exists")

    monkeypatch.setattr(memory, "_create_private_dir", fail)

    def boom(*a, **k):
        raise AssertionError("must not run")

    monkeypatch.setattr(memory.subprocess, "Popen", boom)
    res = _run(tmp_path, reg)
    mod = res.manifest["modules"][0]
    assert mod["status"] == "error" and "private WinPmem directory" in mod["detail"]
    assert events == []


def test_create_private_dir_refuses_off_windows(monkeypatch):
    import pytest

    monkeypatch.setattr(memory.os, "name", "posix")
    with pytest.raises(RuntimeError):
        memory._create_private_dir()


def test_handle_closed_even_when_run_raises(tmp_path, monkeypatch):
    reg, _ = _setup(monkeypatch, tmp_path)
    _popen(monkeypatch, launch_error=OSError("launch failed"))
    _run(tmp_path, reg)
    assert events == ["open", "hash", "run", "close"] and not restricted[0].exists()


def test_interrupt_kills_winpmem_and_marks_incomplete(tmp_path, monkeypatch):
    reg, _ = _setup(monkeypatch, tmp_path)
    made = _popen(monkeypatch, lines=["x\n"], data=b"partial")

    def feed(self, line):
        raise KeyboardInterrupt

    monkeypatch.setattr(memory.WinPmemRun, "feed", feed)
    import pytest

    with pytest.raises(KeyboardInterrupt):
        _run(tmp_path, reg)
    assert made[0].killed and not restricted[0].exists()


def test_memory_progress_is_printed_on_the_console_only(tmp_path, monkeypatch, capsys):
    from investigation.core import console

    monkeypatch.setattr(console, "INTERVAL", 0)
    reg, _ = _setup(monkeypatch, tmp_path)
    gib = 1024 ** 3
    _popen(monkeypatch, lines=[f"max_physical_memory_ {18 * gib}\n", "50% 0x10 ....\n", "100% 0x20 ....\n"])
    res = _run(tmp_path, reg)
    out = capsys.readouterr().out
    assert "[memory] 50% (9.0 of 18.0 GiB)" in out and "[memory] 100% (18.0 of 18.0 GiB)" in out
    assert "[memory] 50%" not in (Path(res.root) / "collection.log").read_text(encoding="utf-8")
