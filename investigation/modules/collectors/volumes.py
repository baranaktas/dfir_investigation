"""Enumerate local volumes for the drive-selection menu."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Volume:
    letter: str
    fstype: str
    size: int
    label: str
    is_system: bool


def list_volumes() -> list[Volume]:
    if os.name != "nt":
        return []
    import psutil

    system = os.environ.get("SystemDrive", "C:").rstrip("\\/").upper()
    out: list[Volume] = []
    for part in psutil.disk_partitions(all=False):
        opts = part.opts.lower()
        if "cdrom" in opts or "remote" in opts or "network" in opts:
            continue
        letter = part.device.rstrip("\\/").upper()
        label = ""
        try:
            import win32api

            label = win32api.GetVolumeInformation(part.device)[0]
        except Exception:
            pass
        try:
            size = psutil.disk_usage(part.mountpoint).total
        except Exception:
            size = 0
        out.append(Volume(letter, part.fstype, size, label, letter == system))
    return out


def device_length(fh) -> int | None:
    """Size of an open raw device via IOCTL_DISK_GET_LENGTH_INFO; None if unavailable."""
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes

        out = ctypes.c_longlong(0)
        returned = wintypes.DWORD(0)
        ok = ctypes.windll.kernel32.DeviceIoControl(
            wintypes.HANDLE(msvcrt.get_osfhandle(fh.fileno())), 0x7405C, None, 0,
            ctypes.byref(out), ctypes.sizeof(out), ctypes.byref(returned), None)
        return out.value if ok else None
    except Exception:
        return None


def _volume_root(path) -> str:
    """X:\\ or \\\\server\\share\\ for path."""
    import ntpath

    return ntpath.splitdrive(ntpath.abspath(str(path)))[0].rstrip("\\") + "\\"


def volume_fstype(path) -> str:
    if os.name != "nt":
        return ""
    try:
        import win32api

        return win32api.GetVolumeInformation(_volume_root(path))[4]
    except Exception:
        return ""


def disks_of(path) -> set[int] | None:
    """Physical disk numbers backing the volume that holds path; None when they cannot be determined."""
    if os.name != "nt":
        return set()
    try:
        import ctypes
        import ntpath
        from ctypes import wintypes

        drive = ntpath.splitdrive(ntpath.abspath(str(path)))[0]
        with open(rf"\\.\{drive}", "rb", buffering=0) as fh:
            import msvcrt

            buf = ctypes.create_string_buffer(4096)
            returned = wintypes.DWORD(0)
            ok = ctypes.windll.kernel32.DeviceIoControl(
                wintypes.HANDLE(msvcrt.get_osfhandle(fh.fileno())), 0x560000, None, 0,
                buf, len(buf), ctypes.byref(returned), None)
            if not ok:
                return None
            import struct

            (n,) = struct.unpack_from("<I", buf, 0)
            return {struct.unpack_from("<I", buf, 8 + 24 * i)[0] for i in range(n)}
    except Exception:
        return None


def physical_disks() -> list[tuple[int, int]]:
    if os.name != "nt":
        return []
    out: list[tuple[int, int]] = []
    for n in range(32):
        try:
            with open(rf"\\.\PhysicalDrive{n}", "rb", buffering=0) as fh:
                out.append((n, device_length(fh) or 0))
        except OSError:
            continue
    return out
