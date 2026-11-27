"""A bare memory image as the analysis input (no file system; the memory parser does the work)."""

from __future__ import annotations

from pathlib import Path
from typing import BinaryIO, Iterator

from investigation.core.module import ModuleMeta, ModuleType, SourceModule
from investigation.core.registry import register
from investigation.core.source import EvidenceSource

MEMORY_SUFFIXES = (".mem", ".vmem", ".dmp", ".lime", ".mddramimage", ".vmss", ".vmsn")


class MemoryEvidence(EvidenceSource):
    def __init__(self, image: Path):
        self.memory_image = Path(image)
        self.name = self.memory_image.name

    def iter_files(self) -> Iterator[str]:
        return iter(())

    def open(self, path: str) -> BinaryIO:
        raise FileNotFoundError(path)


@register
class MemorySource(SourceModule):
    meta = ModuleMeta(
        name="memory_image",
        description="Memory image (.mem/.vmem/.dmp/.lime/...) - use --memory for .raw images",
        type=ModuleType.SOURCE,
        priority=20,
    )

    def can_open(self, path: Path) -> bool:
        path = Path(path)
        return path.is_file() and path.name.casefold().endswith(MEMORY_SUFFIXES)

    def open(self, path: Path) -> MemoryEvidence:
        return MemoryEvidence(Path(path))
