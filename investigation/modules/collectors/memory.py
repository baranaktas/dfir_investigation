"""RAM capture with an embedded, hash-pinned WinPmem binary (never downloaded at run time)."""

from __future__ import annotations

import logging
import hashlib
import os
import platform
import re
import shutil
import secrets
import subprocess
import threading
from pathlib import Path

import psutil

from investigation.core.console import Throttle, say as _say
from investigation.core.module import CollectorModule, ModuleMeta, ModuleType
from investigation.core.package import hash_file
from investigation.core.registry import register
from investigation.core.requirements import Context, Requirement, Status
from investigation.modules.collectors.imaging import check_target
from investigation.core.frozen import resource

log = logging.getLogger("investigation.collect.memory")

WINPMEM_NAME = "winpmem_mini_x64_rc2.exe"
WINPMEM_URL = "https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x64_rc2.exe"
WINPMEM_SHA256 = "a4d516b6fcaf3b5b1d4ee709ce86f8eabf1d8028b3a83101479b7568b933d21b"


def _search_dirs() -> list[Path]:
    return [resource("resources/winpmem")]


def _load_winpmem() -> bytes | None:
    """Bytes of the embedded WinPmem, verified against the pinned sha256 on the very bytes returned."""
    for d in _search_dirs():
        p = d / WINPMEM_NAME
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if hashlib.sha256(data).hexdigest() == WINPMEM_SHA256:
            return data
    return None


def _create_private_dir() -> Path:
    """Atomically create %SystemRoot%\\Temp\\inv-winpmem-<random> with a protected DACL (Administrators and
    SYSTEM only). Any failure, including an already existing name, raises: there is no fallback."""
    if os.name != "nt":
        raise RuntimeError("the private WinPmem directory can only be created on Windows")
    path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp", "inv-winpmem-" + secrets.token_hex(16))
    try:
        import ntsecuritycon as con
        import pywintypes
        import win32file
        import win32security

        dacl = win32security.ACL()
        for sid in (win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid),
                    win32security.CreateWellKnownSid(win32security.WinLocalSystemSid)):
            dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION,
                                       con.OBJECT_INHERIT_ACE | con.CONTAINER_INHERIT_ACE, con.FILE_ALL_ACCESS, sid)
        sd = win32security.SECURITY_DESCRIPTOR()
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        sd.SetSecurityDescriptorControl(win32security.SE_DACL_PROTECTED, win32security.SE_DACL_PROTECTED)
        sa = pywintypes.SECURITY_ATTRIBUTES()
        sa.SECURITY_DESCRIPTOR = sd
        win32file.CreateDirectory(path, sa)
    except Exception as exc:
        raise RuntimeError(f"cannot create the private WinPmem directory {path}: {exc}") from exc
    return Path(path)


def _open_deny_write(path: Path):
    """Handle that denies other writers/deleters (share mode READ only) so the file cannot change after hashing."""
    import win32file

    return win32file.CreateFile(str(path), win32file.GENERIC_READ, win32file.FILE_SHARE_READ, None,
                                win32file.OPEN_EXISTING, 0, None)


def _sha256_of_handle(handle) -> str:
    import win32file

    h = hashlib.sha256()
    while True:
        _, chunk = win32file.ReadFile(handle, 1024 * 1024)
        if not chunk:
            return h.hexdigest()
        h.update(chunk)


def _close_handle(handle) -> None:
    handle.Close()


def winpmem_path() -> Path | None:
    """The embedded WinPmem if present and matching the pinned sha256, else None."""
    for d in _search_dirs():
        p = d / WINPMEM_NAME
        if p.is_file() and hash_file(p, ("sha256",))["sha256"] == WINPMEM_SHA256:
            return p
    return None


class EmbeddedWinPmem(Requirement):
    def describe(self) -> str:
        return "embedded WinPmem"

    def check(self, ctx: Context):
        p = winpmem_path()
        if p:
            return self._result(Status.OK, str(p))
        return self._fail("embedded WinPmem is missing or its sha256 does not match", "rebuild with scripts/fetch_winpmem.py")


class X64(Requirement):
    def describe(self) -> str:
        return "x64 processor"

    def check(self, ctx: Context):
        m = platform.machine()
        if m.upper() in ("AMD64", "X86_64"):
            return self._result(Status.OK, m)
        return self._fail(f"machine is {m}: WinPmem has no ARM64 driver")


_MAX_PHYS = re.compile(r"max_physical_memory_\s*[:=]?\s*(0x[0-9a-fA-F]+|\d+)")
_DRIVER = re.compile(r"extracting driver to\s+(.+?)\s*$", re.IGNORECASE)
_PROGRESS = re.compile(r"^\s*(\d+)%\s*(?:0x[0-9a-fA-F]+)?\s*(\S*)")


class WinPmemRun:
    """What WinPmem printed: every line is logged, progress and unreadable pages are tallied."""

    def __init__(self) -> None:
        self.code = 0
        self.expected: int | None = None
        self.percent = 0
        self.unreadable = 0
        self.driver_path = ""
        self.lines: list[str] = []

    def feed(self, line: str) -> bool:
        """Record one output line; True when it was a progress line."""
        text = line.rstrip("\r\n")
        if not text.strip():
            return False
        log.info("winpmem: %s", text[:2000])
        self.lines.append(text)
        if len(self.lines) > 50:
            del self.lines[0]
        d = _DRIVER.search(text)
        if d:
            self.driver_path = d.group(1).strip().strip('"')
        m = _MAX_PHYS.search(text)
        if m:
            self.expected = int(m.group(1), 0)
        m = _PROGRESS.match(text)
        if m:
            self.percent = int(m.group(1))
            self.unreadable += m.group(2).count("x")
            return True
        return False

    def tail(self, limit: int) -> str:
        return "\n".join(self.lines)[-limit:].strip() or "no output from WinPmem"


@register
class MemoryWinPmem(CollectorModule):
    meta = ModuleMeta(
        name="memory_winpmem",
        description="Physical memory image (WinPmem)",
        type=ModuleType.COLLECTOR,
        platforms=("windows",),
        requires_admin=True,
        requirements=(EmbeddedWinPmem(), X64()),
        category="memory",
        priority=1,
        confirm="RAM capture loads the WinPmem driver temporarily (it is unloaded afterwards and logged). Continue?",
    )

    def collect(self, ctx: Context, out_dir: Path) -> int:
        opts = ctx.options
        extra = opts.get("extra_files", {})
        warnings = opts.get("warnings", [])
        root = Path(opts.get("package_root", out_dir))
        data = _load_winpmem()
        if data is None:
            raise RuntimeError("embedded WinPmem is missing or its sha256 does not match")
        ram = psutil.virtual_memory().total
        problems = check_target(root, ram)
        if problems:
            raise RuntimeError("; ".join(problems))
        raw = root / "memory" / "memory.raw"
        raw.parent.mkdir(parents=True, exist_ok=True)
        timeout = max(3600, ram / (20 * 1024 ** 2))
        priv = _create_private_dir()
        try:
            exe = priv / WINPMEM_NAME
            with open(exe, "xb") as fh:
                fh.write(data)
            guard = _open_deny_write(exe)
            try:
                if _sha256_of_handle(guard) != WINPMEM_SHA256:
                    raise RuntimeError("private WinPmem copy failed sha256 re-check; not executed")
                _say("[memory] capturing RAM with WinPmem (this can take several minutes)")
                warnings.append("WinPmem driver was loaded temporarily for RAM capture")
                try:
                    run = self._run_winpmem(exe, raw, timeout, ram)
                except subprocess.TimeoutExpired:
                    self._mark_incomplete(raw, extra)
                    raise RuntimeError(f"WinPmem timed out after {int(timeout)} s") from None
                except BaseException:
                    self._mark_incomplete(raw, extra)
                    raise
            finally:
                _close_handle(guard)
        finally:
            shutil.rmtree(priv, ignore_errors=True)
        size = raw.stat().st_size if raw.is_file() else 0
        short = run.expected is not None and size < run.expected
        unverified = run.code == 1 and run.expected is None
        if run.code not in (0, 1) or short or unverified or not raw.is_file():
            self._mark_incomplete(raw, extra)
            raise RuntimeError(f"WinPmem failed (exit {run.code}): {run.tail(500)}")
        h = hash_file(raw, ("md5", "sha1", "sha256"))
        extra["memory/memory.raw"] = {
            "sha256": h["sha256"], "size": raw.stat().st_size, "md5": h["md5"], "sha1": h["sha1"],
            "tool": WINPMEM_NAME, "tool_sha256": WINPMEM_SHA256,
        }
        detail = f"{size / 1024 ** 3:.1f} GiB"
        if run.driver_path:
            extra["memory/memory.raw"]["driver_path"] = run.driver_path
        if run.unreadable:
            extra["memory/memory.raw"]["unreadable_pages"] = run.unreadable
        if run.code != 0:
            extra["memory/memory.raw"]["winpmem_exit"] = run.code
        if run.unreadable:
            detail += f", {run.unreadable} unreadable pages"
        opts.get("module_detail", {})[self.meta.name] = detail
        return 1

    @staticmethod
    def _run_winpmem(exe: Path, raw: Path, timeout: float, ram: int = 0) -> "WinPmemRun":
        """Run WinPmem, logging and parsing its output as it arrives. Raises TimeoutExpired after killing it."""
        run = WinPmemRun()
        proc = subprocess.Popen([str(exe), str(raw)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace")
        expired = threading.Event()

        def stop() -> None:
            expired.set()
            proc.kill()

        timer = threading.Timer(timeout, stop)
        timer.daemon = True
        timer.start()
        try:
            throttle = Throttle()
            for line in proc.stdout:
                if run.feed(line) and throttle.ready():
                    total = run.expected or ram
                    if total:
                        gib = 1024 ** 3
                        _say(f"[memory] {run.percent}% ({total * run.percent / 100 / gib:.1f} of {total / gib:.1f} GiB)")
                    else:
                        _say(f"[memory] {run.percent}%")
            run.code = proc.wait()
        finally:
            timer.cancel()
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        if expired.is_set():
            raise subprocess.TimeoutExpired(str(exe), timeout)
        return run

    @staticmethod
    def _mark_incomplete(raw: Path, extra: dict) -> None:
        if raw.is_file():
            extra["memory/memory.raw"] = {"incomplete": True, "tool": WINPMEM_NAME}
