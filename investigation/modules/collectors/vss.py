"""Copy forensic artifacts from existing Volume Shadow Copies (read-only; none are created or deleted)."""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import BinaryIO

from investigation.core.console import Throttle, human_bytes, say as _say
from investigation.core.module import CollectorModule, ModuleMeta, ModuleType
from investigation.core.registry import register
from investigation.core.requirements import Context
from investigation.modules.collectors.base import write_csv
from investigation.modules.collectors.files import (AlignedVolume, FilesCollector, NtfsReader, expand,
                                                    load_targets)
from investigation.modules.collectors.volumes import device_length
from investigation.modules.collectors.wmi import WmiUnavailable, cim_to_utc, wmi_query

log = logging.getLogger("investigation.collect")


@dataclass
class Shadow:
    index: int
    device: str
    volume_letter: str
    created_utc: datetime | None
    id: str


def list_shadows() -> list[Shadow]:
    letters = {str(v.get("DeviceID") or "").lower(): str(v.get("DriveLetter") or "").rstrip(":").upper()
               for v in wmi_query("root\\cimv2", "Win32_Volume", ["DeviceID", "DriveLetter"])}
    out = []
    for r in wmi_query("root\\cimv2", "Win32_ShadowCopy", ["ID", "DeviceObject", "VolumeName", "InstallDate"]):
        device = str(r.get("DeviceObject") or "")
        m = re.search(r"(\d+)$", device)
        letter = letters.get(str(r.get("VolumeName") or "").lower(), "")
        if not m or not letter:
            continue
        out.append(Shadow(int(m.group(1)), device, letter, cim_to_utc(r.get("InstallDate")),
                          str(r.get("ID") or "")))
    return out


def open_shadow(device: str) -> BinaryIO:
    """Open a shadow by its GLOBALROOT device path (shadow devices usually have no DosDevices link)."""
    return open(device, "rb", buffering=0)


def _reader_for(fh: BinaryIO) -> NtfsReader:
    try:
        vol = AlignedVolume(fh, device_length(fh))
    except BaseException:
        fh.close()
        raise
    try:
        return NtfsReader(vol)
    except BaseException:
        vol.close()
        raise


@register
class VssCollector(CollectorModule):
    meta = ModuleMeta(
        name="vss",
        description="Copy forensic files from existing volume shadow copies",
        type=ModuleType.COLLECTOR,
        platforms=("windows",),
        requires_admin=True,
        category="vss",
        priority=110,
    )

    def collect(self, ctx: Context, out_dir: Path) -> int:
        opts = ctx.options
        extra = opts.get("extra_files", {})
        warnings = opts.get("warnings", [])
        root = Path(opts.get("package_root", out_dir))
        hook = opts.get("vss_readers")
        drives = {str(d).rstrip(":\\/").upper() for d in (
            opts.get("drives") or [os.environ.get("SystemDrive", "C:")])}
        cols = ("index", "id", "volume", "created_utc")
        try:
            shadows = [s for s in list_shadows() if s.volume_letter in drives]
        except Exception as exc:
            msg = f"shadow copies could not be listed: {type(exc).__name__}: {exc}"
            log.warning(msg)
            warnings.append(msg)
            write_csv(root / "vss" / "shadows.csv", cols, [])
            return 0
        write_csv(root / "vss" / "shadows.csv", cols,
                  [{"index": s.index, "id": s.id, "volume": s.volume_letter, "created_utc": s.created_utc}
                   for s in shadows])
        targets = [t for t in load_targets() if not t.get("raw_only")]
        copied = 0

        for number, s in enumerate(shadows, 1):
            stats: dict = {}
            throttle = Throttle()

            def line() -> str:
                return (f"[vss] shadow {number}/{len(shadows)} ({s.volume_letter}:): {stats.get('files', 0)} files, "
                        f"{human_bytes(stats.get('bytes', 0))}, {stats.get('unchanged', 0)} unchanged")

            def problem(path: str, exc: Exception) -> None:
                msg = f"vss {s.index} {s.volume_letter}:{path} skipped: {type(exc).__name__}: {exc}"
                log.warning(msg)
                warnings.append(msg)

            reader = None
            try:
                reader = hook[s.index][1] if hook is not None else _reader_for(open_shadow(s.device))
            except Exception as exc:
                msg = f"shadow {s.index} cannot be opened: {type(exc).__name__}: {exc}"
                log.warning(msg)
                warnings.append(msg)
                continue
            before = set(extra)
            try:
                for target in targets:
                    for pattern in target["paths"]:
                        try:
                            for rel in expand(reader, pattern, problem):
                                copied += FilesCollector._one(reader, s.volume_letter, rel, root, extra,
                                                              prefix=f"vss/{s.index}",
                                                              dedupe_against="files", stats=stats)
                                if throttle.ready():
                                    _say(line())
                        except Exception as exc:
                            problem(pattern, exc)
                _say(line())
            finally:
                if hook is None and hasattr(reader, "close"):
                    reader.close()
            for key in set(extra) - before:
                extra[key]["shadow_id"] = s.id
                extra[key]["shadow_created_utc"] = s.created_utc.isoformat() if s.created_utc else ""
        return copied
