import sys
import types
from pathlib import Path

import psutil

from investigation.modules.collectors import authenticode, live


class FakeProc:
    def __init__(self, info, exe_denied=False):
        self._info = info
        self._denied = exe_denied

    @property
    def info(self):
        if self._denied:
            return {**self._info, "exe": None, "cmdline": None}
        return self._info


class Vanishing:
    @property
    def info(self):
        raise psutil.NoSuchProcess(99)


def _info(pid, exe="C:\\a.exe"):
    return {"pid": pid, "ppid": 1, "name": "a.exe", "exe": exe, "cmdline": ["a.exe", "-x"],
            "username": "U", "create_time": 1700000000.0}


def test_processes_rows_handle_access_denied_and_vanished(monkeypatch):
    procs = [FakeProc(_info(1)), Vanishing(), FakeProc(_info(2), exe_denied=True)]
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: iter(procs))
    monkeypatch.setattr(live, "_sha256", lambda p: "h")
    monkeypatch.setattr(authenticode, "signature_status", lambda p: "")
    rows = list(live.Processes().rows(None))
    assert [r["pid"] for r in rows] == [1, 2]
    assert rows[1]["exe"] == "" and rows[1]["sha256"] == ""
    assert rows[0]["create_time_utc"].tzinfo is not None


def test_process_hash_cached_per_path(monkeypatch, tmp_path):
    f = tmp_path / "a.exe"
    f.write_bytes(b"x")
    procs = [FakeProc(_info(1, str(f))), FakeProc(_info(2, str(f)))]
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: iter(procs))
    monkeypatch.setattr(authenticode, "signature_status", lambda p: "")
    opened = []
    monkeypatch.setattr(live, "is_remote_path", lambda p: False)
    import builtins
    real_open = builtins.open

    def spy(path, *a, **k):
        if str(path) == str(f):
            opened.append(path)
        return real_open(path, *a, **k)

    monkeypatch.setattr(builtins, "open", spy)
    rows = list(live.Processes().rows(None))
    assert len(opened) == 1
    assert rows[0]["sha256"] == rows[1]["sha256"] != ""


def test_network_rows_include_process_name(monkeypatch):
    A = types.SimpleNamespace
    conns = [A(type=1, laddr=("1.1.1.1", 80), raddr=("2.2.2.2", 5), status="ESTABLISHED", pid=7),
             A(type=2, laddr=("0.0.0.0", 53), raddr=(), status="NONE", pid=None)]
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": conns)
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: iter([FakeProc({"pid": 7, "name": "svc.exe"})]))
    rows = list(live.Network().rows(None))
    assert rows[0]["process"] == "svc.exe" and rows[0]["proto"] == "tcp" and rows[0]["remote_port"] == 5
    assert rows[1]["proto"] == "udp" and rows[1]["remote_addr"] == ""


def _enum(key, i):
    try:
        return {("L", 0): ("Path", "x", 1), ("C", 0): ("TEMP", "y", 1)}[(key, i)]
    except KeyError:
        raise OSError


def test_env_reads_both_scopes(monkeypatch):
    fake = types.SimpleNamespace(
        HKEY_LOCAL_MACHINE="L", HKEY_CURRENT_USER="C", KEY_READ=1,
        OpenKey=lambda root, sub, *a: root,
        EnumValue=_enum,
        CloseKey=lambda k: None,
    )
    monkeypatch.setitem(sys.modules, "winreg", fake)
    rows = list(live.Env().rows(None))
    assert {(r["scope"], r["name"], r["value"]) for r in rows} == {("system", "Path", "x"), ("user", "TEMP", "y")}


def test_system_info_has_required_keys():
    rows = list(live.SystemInfo().rows(None))
    keys = [r["key"] for r in rows]
    for k in ("hostname", "os_caption", "os_version", "os_build", "architecture", "boot_time_utc",
              "uptime_seconds", "local_timezone", "utc_offset", "collector_user", "is_admin", "collected_utc"):
        assert k in keys


def test_signature_status_empty_off_windows(monkeypatch):
    monkeypatch.setattr(authenticode.os, "name", "posix")
    assert authenticode.signature_status("C:\\x.exe") == ""


def test_is_remote_path_deny_by_default():
    fixed = lambda root: 3
    for p in ("\\\\srv\\share\\a.exe", "\\\\?\\UNC\\srv\\share\\a.exe",
              "\\\\?\\GLOBALROOT\\Device\\Mup\\s\\x.exe", "\\\\.\\GLOBALROOT\\Device\\Mup\\s\\x.exe",
              "\\??\\UNC\\s\\x.exe", "\\Device\\Mup\\s\\x.exe",
              "\\\\?\\Volume{1234}\\x.exe", "x.exe", "..\\x.exe", ""):
        assert live.is_remote_path(p, fixed), p
    assert not live.is_remote_path("C:\\x.exe", fixed)
    assert not live.is_remote_path("\\\\?\\C:\\x.exe", fixed)
    assert not live.is_remote_path("\\\\.\\C:\\x.exe", fixed)
    assert live.is_remote_path("Z:\\x.exe", lambda r: 4)
    assert live.is_remote_path("Z:\\x.exe", lambda r: 0)

    def boom(r):
        raise OSError

    assert live.is_remote_path("C:\\x.exe", boom)


def test_remote_exe_not_hashed_or_verified(monkeypatch):
    procs = [FakeProc(_info(1, "\\\\evil\\s\\a.exe"))]
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: iter(procs))
    monkeypatch.setattr(live, "_sha256", lambda p: 1 / 0)
    monkeypatch.setattr(authenticode, "signature_status", lambda p: 1 / 0)
    row = list(live.Processes().rows(None))[0]
    assert row["sha256"] == "" and row["signed"] == "remote-skipped"


def test_cmdline_is_joined_string(monkeypatch):
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: iter([FakeProc(_info(1))]))
    monkeypatch.setattr(live, "_sha256", lambda p: "")
    monkeypatch.setattr(authenticode, "signature_status", lambda p: "")
    assert list(live.Processes().rows(None))[0]["cmdline"] == "a.exe -x"


def test_utc_offset_format():
    assert live._fmt_offset(-5 * 3600) == "-05:00"
    assert live._fmt_offset(19800) == "+05:30"
    assert live._fmt_offset(0) == "+00:00"


def test_clipboard_lone_surrogate_does_not_crash(monkeypatch, tmp_path):
    cb = types.SimpleNamespace(OpenClipboard=lambda: None, CloseClipboard=lambda: None, CF_UNICODETEXT=13,
                               IsClipboardFormatAvailable=lambda f: True,
                               GetClipboardData=lambda f: "a\ud800b")
    monkeypatch.setitem(sys.modules, "win32clipboard", cb)
    live.Clipboard().collect(None, tmp_path)
    assert (tmp_path / "volatile" / "clipboard.txt").exists()


def test_member_tag_and_classification():
    assert authenticode.member_tag(b"\x01\xab\xff") == "01ABFF"
    assert authenticode.classify_result(0) == "signed"
    assert authenticode.classify_result(0x800B0100) == "unsigned"
    assert authenticode.classify_result(0x800B0001) == "error"
    assert authenticode.classify_result(0x80096010) == "error"
    assert authenticode.PROV_FLAGS == 0x1010


def test_pseudo_process_without_file_is_blank_not_remote(monkeypatch):
    procs = [FakeProc(_info(1, "Registry")), FakeProc(_info(2, "MemCompression"))]
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: iter(procs))
    monkeypatch.setattr(live, "_sha256", lambda p: 1 / 0)
    monkeypatch.setattr(authenticode, "signature_status", lambda p: 1 / 0)
    rows = list(live.Processes().rows(None))
    assert [(r["sha256"], r["signed"]) for r in rows] == [("", ""), ("", "")]
