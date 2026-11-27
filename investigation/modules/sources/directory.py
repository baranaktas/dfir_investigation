"""A plain directory (e.g. a mounted image, an extracted collection, a folder of logs)."""

from __future__ import annotations

import os
import stat as stat_mod
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterator

from investigation.core.module import ModuleMeta, ModuleType, SourceModule
from investigation.core.registry import register
from investigation.core.source import EvidenceSource


class DirectoryEvidence(EvidenceSource):
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.name = self.root.name
        self._errors: dict[str, None] = {}

    def _walk_error(self, exc: OSError) -> None:
        where = exc.filename or "?"
        try:
            where = Path(where).resolve().relative_to(self.root).as_posix()
        except (ValueError, OSError):
            pass
        self._errors[f"cannot read {where}: {exc.strerror or exc}"] = None

    def access_errors(self) -> list[str]:
        return list(self._errors)

    def iter_files(self) -> Iterator[str]:
        for dirpath, dirnames, filenames in os.walk(self.root, onerror=self._walk_error):
            dirnames.sort()
            rel = Path(dirpath).relative_to(self.root)
            for f in sorted(filenames):
                try:
                    if not stat_mod.S_ISREG(os.lstat(os.path.join(dirpath, f)).st_mode):
                        continue
                except OSError:
                    continue
                yield (rel / f).as_posix() if rel.parts else f

    def stat(self, path: str):
        full = (self.root / path).resolve()
        if not full.is_relative_to(self.root):
            return None, None
        try:
            st = full.stat()
        except OSError:
            return None, None
        return st.st_size, datetime.fromtimestamp(st.st_mtime, timezone.utc)

    def open(self, path: str) -> BinaryIO:
        full = (self.root / path).resolve()
        if not full.is_relative_to(self.root):
            raise ValueError(f"path escapes evidence root: {path}")
        if not stat_mod.S_ISREG(full.stat().st_mode):
            raise ValueError(f"not a regular file: {path}")
        return open(full, "rb")


@register
class DirectorySource(SourceModule):
    meta = ModuleMeta(
        name="directory",
        description="Open a directory (mounted image, extracted collection, folder of artifacts)",
        type=ModuleType.SOURCE,
    )

    def can_open(self, path: Path) -> bool:
        return Path(path).is_dir()

    def open(self, path: Path) -> DirectoryEvidence:
        return DirectoryEvidence(Path(path))
