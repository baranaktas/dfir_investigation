"""Physical disk imaging (read-only, three hashes) into the collection package."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import BinaryIO

from investigation.core.console import say as _say
from investigation.core.module import CollectorModule, ModuleMeta, ModuleType
from investigation.core.registry import register
from investigation.core.requirements import Context
from investigation.modules.collectors.files import AlignedVolume
from investigation.modules.collectors.imaging import check_target, copy_device, write_hash_file
from investigation.modules.collectors.volumes import disks_of, physical_disks

log = logging.getLogger("investigation.collect.disk")


def open_disk(index: int, size: int | None = None) -> BinaryIO:
    """Read-only aligned handle on \\\\.\\PhysicalDriveN (tests monkeypatch this)."""
    raw = open(rf"\\.\PhysicalDrive{index}", "rb", buffering=0)
    try:
        return AlignedVolume(raw, size)
    except BaseException:
        raw.close()
        raise


@register
class DiskImage(CollectorModule):
    meta = ModuleMeta(
        name="disk_image",
        description="Raw image of the physical disk(s) behind the selected drives",
        type=ModuleType.COLLECTOR,
        platforms=("windows",),
        requires_admin=True,
        category="disk",
        priority=200,
        confirm="Disk imaging reads the whole disk and can take hours. Continue?",
    )

    def collect(self, ctx: Context, out_dir: Path) -> int:
        opts = ctx.options
        extra = opts.get("extra_files", {})
        warnings = opts.get("warnings", [])
        details = opts.setdefault("module_detail", {})
        root = Path(opts.get("package_root", out_dir))
        drives = opts.get("image_drives") or opts.get("drives") or [os.environ.get("SystemDrive", "C:")]
        sizes = dict(physical_disks())
        wanted: set[int] = set()
        notes: list[str] = []

        def note(msg: str) -> None:
            log.warning(msg)
            _say(f"[warn] {msg}")
            warnings.append(msg)
            notes.append(msg)

        for d in drives:
            letter = str(d).rstrip(":\\/").upper()
            found = disks_of(f"{letter}:\\")
            if found is None:
                note(f"cannot determine the physical disk behind {letter}:; skipped")
            else:
                wanted |= found
        done = 0
        incomplete = False
        for n in sorted(wanted):
            size = sizes.get(n, 0)
            if not size:
                note(f"PhysicalDrive{n}: size unknown; skipped")
                continue
            problems = check_target(root, size, n)
            if problems:
                for p in problems:
                    note(f"PhysicalDrive{n} not imaged: {p}")
                continue
            ok = self._image(n, size, root, extra, note)
            done += 1
            incomplete = incomplete or not ok
        if done == 0:
            opts["force_partial"] = "no disk image was produced"
            warnings.append("disk imaging selected but no disk image was produced")
        elif incomplete:
            opts["force_partial"] = "a disk image is incomplete"
            warnings.append("a disk image is incomplete")
        if notes:
            details["disk_image"] = "; ".join(notes)
        return done

    @staticmethod
    def _image(n: int, size: int, root: Path, extra: dict, note) -> bool:
        """Image one disk; True when the image is complete."""
        rel = f"disk/PhysicalDrive{n}.dd"
        (root / "disk").mkdir(parents=True, exist_ok=True)
        step = {"next": 5}

        def progress(done: int) -> None:
            pct = done * 100 // size
            while pct >= step["next"] <= 100:
                _say(f"[disk] PhysicalDrive{n}: {step['next']}%")
                step["next"] += 5

        src = open_disk(n, size)
        try:
            res = copy_device(src, size, root / rel, on_progress=progress)
        except BaseException as exc:
            part = getattr(exc, "partial", None)
            if part is not None:
                extra[rel] = {"sha256": part.sha256, "size": part.size, "md5": part.md5, "sha1": part.sha1,
                              "bad_ranges": [list(r) for r in part.bad_ranges], "incomplete": True,
                              "source_path": rf"\\.\PhysicalDrive{n}"}
            else:
                extra[rel] = {"incomplete": True, "source_path": rf"\\.\PhysicalDrive{n}"}
            raise
        finally:
            src.close()
        write_hash_file(res)
        if res.incomplete:
            note(f"PhysicalDrive{n} image INCOMPLETE ({res.size} of {size} bytes)")
        if res.bad_ranges:
            note(f"PhysicalDrive{n}: {len(res.bad_ranges)} unreadable ranges zero-filled")
        extra[rel] = {"sha256": res.sha256, "size": res.size, "md5": res.md5, "sha1": res.sha1, "bad_ranges": [list(r) for r in res.bad_ranges],
                      "incomplete": res.incomplete, "source_path": rf"\\.\PhysicalDrive{n}"}
        log.info("imaged PhysicalDrive%d: %d bytes, %d bad ranges", n, res.size, len(res.bad_ranges))
        return not res.incomplete
