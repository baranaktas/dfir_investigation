"""Live (volatile) data collectors: processes, network, sessions, DLLs, pipes, env, clipboard, system info."""

from __future__ import annotations

import getpass
import hashlib
import os
import platform
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

import psutil

from investigation.core.module import CollectorModule, ModuleMeta, ModuleType
from investigation.core.registry import register
from investigation.core.requirements import Context, is_admin
from investigation.modules.collectors import authenticode
from investigation.modules.collectors.base import VolatileCollector


def _meta(name: str, description: str, priority: int) -> ModuleMeta:
    return ModuleMeta(name=name, description=description, type=ModuleType.COLLECTOR,
                      platforms=("windows",), priority=priority, category="live")


def _utc(ts: float | None) -> datetime | None:
    return datetime.fromtimestamp(ts, timezone.utc) if ts else None


def _fmt_offset(seconds: int) -> str:
    sign = "-" if seconds < 0 else "+"
    m = abs(int(seconds)) // 60
    return f"{sign}{m // 60:02d}:{m % 60:02d}"


def _sha256(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _drive_type(root: str) -> int:
    import ctypes

    return int(ctypes.windll.kernel32.GetDriveTypeW(root))


_LOCAL_DRIVE_TYPES = (2, 3, 5, 6)


def is_remote_path(path: str, drive_type=None) -> bool:
    """Deny by default: local only for X:\\... or \\\\?\\X:\\... / \\\\.\\X:\\... on a known local drive type."""
    try:
        p = str(path).replace("/", "\\")
        if p[:4] in ("\\\\?\\", "\\\\.\\"):
            p = p[4:]
        if len(p) < 3 or not (p[0].isascii() and p[0].isalpha()) or p[1:3] != ":\\":
            return True
        return (drive_type or _drive_type)(p[:2] + "\\") not in _LOCAL_DRIVE_TYPES
    except Exception:
        return True


@register
class Processes(VolatileCollector):
    meta = _meta("processes", "Running processes with hash and signature status", 10)
    filename = "processes.csv"
    columns = ("pid", "ppid", "name", "exe", "cmdline", "user", "create_time_utc", "sha256", "signed")

    def rows(self, ctx: Context) -> Iterable[Mapping[str, Any]]:
        attrs = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]
        hashes: dict[str, str] = {}
        sigs: dict[str, str] = {}
        for proc in psutil.process_iter(attrs):
            try:
                info = proc.info
            except psutil.NoSuchProcess:
                continue
            except psutil.AccessDenied:
                continue
            exe = info.get("exe") or ""
            if exe and exe not in hashes:
                if not any(sep in exe for sep in ("\\", "/", ":")):
                    hashes[exe], sigs[exe] = "", ""
                elif is_remote_path(exe):
                    hashes[exe], sigs[exe] = "", "remote-skipped"
                else:
                    hashes[exe] = _sha256(exe)
                    sigs[exe] = authenticode.signature_status(exe)
            yield {
                "pid": info.get("pid"), "ppid": info.get("ppid"), "name": info.get("name") or "",
                "exe": exe, "cmdline": " ".join(info.get("cmdline") or ()), "user": info.get("username") or "",
                "create_time_utc": _utc(info.get("create_time")),
                "sha256": hashes.get(exe, ""), "signed": sigs.get(exe, ""),
            }


@register
class Network(VolatileCollector):
    meta = _meta("network", "Network connections with owning process", 20)
    filename = "network.csv"
    columns = ("proto", "local_addr", "local_port", "remote_addr", "remote_port", "state", "pid", "process")

    def rows(self, ctx: Context) -> Iterable[Mapping[str, Any]]:
        names: dict[int, str] = {}
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                names[proc.info["pid"]] = proc.info["name"] or ""
            except Exception:
                continue
        for c in psutil.net_connections("inet"):
            laddr, raddr = c.laddr or (), c.raddr or ()
            yield {
                "proto": "tcp" if int(c.type) == 1 else "udp",
                "local_addr": laddr[0] if laddr else "", "local_port": laddr[1] if laddr else "",
                "remote_addr": raddr[0] if raddr else "", "remote_port": raddr[1] if raddr else "",
                "state": c.status, "pid": c.pid, "process": names.get(c.pid, "") if c.pid else "",
            }


@register
class Sessions(VolatileCollector):
    meta = _meta("sessions", "Logged-on user sessions", 30)
    filename = "sessions.csv"
    columns = ("user", "terminal", "host", "started_utc")

    def rows(self, ctx: Context) -> Iterable[Mapping[str, Any]]:
        for u in psutil.users():
            yield {"user": u.name, "terminal": u.terminal or "", "host": u.host or "", "started_utc": _utc(u.started)}


@register
class Dlls(VolatileCollector):
    meta = _meta("dlls", "Loaded modules per process", 40)
    filename = "dlls.csv"
    columns = ("pid", "process", "path")

    def rows(self, ctx: Context) -> Iterable[Mapping[str, Any]]:
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid, name = proc.info["pid"], proc.info["name"] or ""
                maps = proc.memory_maps(grouped=True)
            except Exception:
                continue
            for m in maps:
                if m.path.lower().endswith((".dll", ".exe", ".sys")):
                    yield {"pid": pid, "process": name, "path": m.path}


@register
class Pipes(VolatileCollector):
    meta = _meta("pipes", "Named pipes", 40)
    filename = "pipes.csv"
    columns = ("name",)

    def rows(self, ctx: Context) -> Iterable[Mapping[str, Any]]:
        for name in os.listdir("\\\\.\\pipe\\"):
            yield {"name": name}


@register
class Env(VolatileCollector):
    meta = _meta("env", "System and user environment variables (registry)", 60)
    filename = "env.csv"
    columns = ("scope", "name", "value")

    def rows(self, ctx: Context) -> Iterable[Mapping[str, Any]]:
        import winreg

        for scope, root, sub in (
            ("system", winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
            ("user", winreg.HKEY_CURRENT_USER, "Environment"),
        ):
            try:
                key = winreg.OpenKey(root, sub, 0, winreg.KEY_READ)
            except OSError:
                continue
            try:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    yield {"scope": scope, "name": name, "value": value}
                    i += 1
            finally:
                winreg.CloseKey(key)


@register
class Clipboard(CollectorModule):
    meta = _meta("clipboard", "Clipboard text", 60)

    def collect(self, ctx: Context, out_dir: Path) -> int:
        text = ""
        try:
            import win32clipboard

            win32clipboard.OpenClipboard()
            try:
                if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
                    text = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT) or ""
            finally:
                win32clipboard.CloseClipboard()
        except Exception:
            text = ""
        path = Path(out_dir) / "volatile" / "clipboard.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", errors="replace")
        return 1 if text else 0


@register
class SystemInfo(VolatileCollector):
    meta = _meta("system_info", "Host, OS, time and collector context", 5)
    filename = "system_info.csv"
    columns = ("key", "value")

    def rows(self, ctx: Context) -> Iterable[Mapping[str, Any]]:
        now = datetime.now(timezone.utc)
        boot = datetime.fromtimestamp(psutil.boot_time(), timezone.utc)
        release, version, _csd, _ptype = platform.win32_ver()
        edition = platform.win32_edition() if hasattr(platform, "win32_edition") else ""
        offset = -(time.altzone if time.daylight and time.localtime().tm_isdst > 0 else time.timezone)
        try:
            user = getpass.getuser()
        except Exception:
            user = os.environ.get("USERNAME", "")
        caption = " ".join(p for p in ("Windows", release, edition) if p)
        build = version.split(".")[-1] if version.count(".") >= 2 else ""
        try:
            from investigation.modules.collectors import wmi

            os_row = wmi.wmi_query("root\\cimv2", "Win32_OperatingSystem", ["Caption", "Version", "BuildNumber"])[0]
            caption = os_row.get("Caption") or caption
            version = os_row.get("Version") or version
            build = str(os_row.get("BuildNumber") or "") or build
        except Exception:
            pass
        items = {
            "hostname": platform.node(),
            "os_caption": caption,
            "os_version": version,
            "os_build": build,
            "architecture": platform.machine(),
            "boot_time_utc": boot,
            "uptime_seconds": int((now - boot).total_seconds()),
            "local_timezone": time.tzname[1] if time.daylight and time.localtime().tm_isdst > 0 else time.tzname[0],
            "utc_offset": _fmt_offset(offset),
            "collector_user": user,
            "is_admin": is_admin(),
            "collected_utc": now,
        }
        for k, v in items.items():
            yield {"key": k, "value": v}
