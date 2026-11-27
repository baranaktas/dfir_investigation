"""Raw device imaging: three hashes while reading, bad-sector zero-fill, target checks."""

from __future__ import annotations

import hashlib
import logging
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable

from investigation.modules.collectors.files import win_long_path
from investigation.modules.collectors.volumes import disks_of, volume_fstype

log = logging.getLogger("investigation.collect.imaging")

GIB = 1024 ** 3


@dataclass
class ImageResult:
    path: Path
    size: int
    md5: str
    sha1: str
    sha256: str
    bad_ranges: list[tuple[int, int]]
    incomplete: bool


def _open_dest(path: Path):
    return open(win_long_path(path), "wb", buffering=0)


def _add_bad(ranges: list[tuple[int, int]], off: int, n: int) -> None:
    if ranges and ranges[-1][0] + ranges[-1][1] == off:
        ranges[-1] = (ranges[-1][0], ranges[-1][1] + n)
    else:
        ranges.append((off, n))


def copy_device(src: BinaryIO, size: int, dest: Path, chunk: int = 4 * 1024 * 1024, sector: int = 4096,
                on_progress: Callable[[int], None] | None = None) -> ImageResult:
    hashes = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]
    bad: list[tuple[int, int]] = []
    done = 0
    incomplete = False
    interrupted: KeyboardInterrupt | None = None
    out = _open_dest(dest)
    try:
        while done < size:
            want = min(chunk, size - done)
            try:
                data = src.read(want)
            except OSError:
                data = b""
                for off in range(0, want, sector):
                    n = min(sector, want - off)
                    try:
                        src.seek(done + off)
                        part = src.read(n)
                    except OSError:
                        part = b""
                    if len(part) < n:
                        _add_bad(bad, done + off, n)
                        log.warning("unreadable bytes at offset %d (%d bytes), zero-filled", done + off, n)
                        part = part.ljust(n, b"\0")
                    data += part
            if not data:
                break
            try:
                view = memoryview(data)
                while view:
                    view = view[out.write(view):]
            except OSError as exc:
                log.warning("write failed at offset %d (%s); image incomplete", done, exc)
                incomplete = True
                try:
                    out.truncate(done)
                except OSError:
                    pass
                break
            for h in hashes:
                h.update(data)
            done += len(data)
            if on_progress:
                on_progress(done)
    except KeyboardInterrupt as exc:
        interrupted = exc
        try:
            out.truncate(done)
        except OSError:
            pass
    finally:
        try:
            out.close()
        except OSError as exc:
            log.warning("closing %s failed (%s); image incomplete", dest, exc)
            incomplete = True
    if done < size:
        incomplete = True
    result = ImageResult(Path(dest), done, *(h.hexdigest() for h in hashes), bad, incomplete or interrupted is not None)
    if interrupted is not None:
        interrupted.partial = result
        raise interrupted
    return result


def write_hash_file(result: ImageResult) -> Path:
    path = result.path.with_name(result.path.name + ".hashes.txt")
    path.write_text(f"md5  {result.md5}\nsha1  {result.sha1}\nsha256  {result.sha256}\n"
                    f"size  {result.size}\nbad_ranges  {len(result.bad_ranges)}\n", encoding="utf-8")
    return path


def check_target(out_dir: Path, needed: int, source_disk: int | None = None) -> list[str]:
    problems: list[str] = []
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(out_dir).free
    if free - GIB < needed:
        problems.append(f"not enough free space: {free} bytes free, {needed} needed plus 1 GiB reserve")
    if volume_fstype(out_dir) == "FAT32" and needed > 4 * GIB - 1:
        problems.append("target is FAT32: a file over 4 GiB cannot be stored")
    if source_disk is not None and not str(out_dir).startswith("\\\\"):
        disks = disks_of(out_dir)
        if disks is None:
            problems.append("cannot determine which disk holds the output; refusing to image")
        elif source_disk in disks:
            problems.append(f"output is on the source disk (PhysicalDrive{source_disk}); choose another drive")
    return problems
