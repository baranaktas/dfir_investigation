"""Compress a finished collection package into a zip next to its folder."""

from __future__ import annotations

import hashlib
import os
import shutil
import zipfile
from pathlib import Path
from typing import Callable

from investigation.core.console import Throttle, human_bytes, say

CHUNK = 1024 * 1024


class ZipSkipped(Exception):
    """The zip was not made (for example, not enough free space)."""


def _files(root: Path) -> list[tuple[Path, int]]:
    out = []
    for dirpath, _dirs, names in os.walk(root):
        for n in sorted(names):
            p = Path(dirpath) / n
            out.append((p, p.stat().st_size))
    return sorted(out)


def sidecar_for(zip_path: Path) -> Path:
    return zip_path.with_name(zip_path.name + ".sha256")


def zip_package(root: Path, progress: Callable[[str], None] = say) -> tuple[Path, Path]:
    """Write <root>.zip (every file under one top folder, manifest unchanged) and <root>.zip.sha256.
    Returns both paths. Raises ZipSkipped when the drive cannot hold it; a partial zip is removed on any failure."""
    root = Path(root)
    zip_path = root.with_name(root.name + ".zip")
    files = _files(root)
    total = sum(size for _, size in files)
    free = shutil.disk_usage(zip_path.parent).free
    if free < total:
        raise ZipSkipped(f"not enough free space for the zip: about {human_bytes(total)} needed, "
                         f"{human_bytes(free)} free")
    throttle = Throttle()
    done = 0

    def report(final: bool = False) -> None:
        if total and (final or throttle.ready()):
            progress(f"[zip] {int(done * 100 / total)}% ({human_bytes(done)} of {human_bytes(total)})")

    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for path, _size in files:
                arc = f"{root.name}/{path.relative_to(root).as_posix()}"
                info = zipfile.ZipInfo.from_file(path, arc)
                info.compress_type = zipfile.ZIP_DEFLATED
                with open(path, "rb") as src, zf.open(info, "w", force_zip64=True) as dst:
                    while chunk := src.read(CHUNK):
                        dst.write(chunk)
                        done += len(chunk)
                        report()
        report(final=True)
        digest = hashlib.sha256()
        with open(zip_path, "rb") as fh:
            while chunk := fh.read(CHUNK):
                digest.update(chunk)
        sidecar = sidecar_for(zip_path)
        sidecar.write_text(f"{digest.hexdigest()}  {zip_path.name}\n", encoding="utf-8")
    except BaseException:
        try:
            zip_path.unlink()
        except OSError:
            pass
        raise
    return zip_path, sidecar
