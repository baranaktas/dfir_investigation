"""Evidence sources: a read-only, case-insensitive view of the files inside an input."""

from __future__ import annotations

import re
from datetime import datetime
from abc import ABC, abstractmethod
from functools import lru_cache
from typing import BinaryIO, Iterator


@lru_cache(maxsize=256)
def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a '/'-separated glob (with '**') into a case-insensitive regex."""
    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z", re.IGNORECASE | re.DOTALL)


class EvidenceSource(ABC):
    """Paths are relative, '/'-separated. Implementations must never open files for writing."""

    name: str = ""
    is_system: bool = False

    @abstractmethod
    def iter_files(self) -> Iterator[str]:
        """All file paths inside the source."""

    def glob(self, pattern: str) -> Iterator[str]:
        rx = glob_to_regex(pattern)
        for path in self.iter_files():
            if rx.match(path):
                yield path

    @abstractmethod
    def open(self, path: str) -> BinaryIO: ...

    def stat(self, path: str) -> tuple[int | None, "datetime | None"]:
        """(size, modification time UTC) of a file, when known."""
        return None, None

    def system_info(self) -> dict[str, str]:
        """Host facts (hostname, os, version, timezone, ...) when the source knows them."""
        return {}

    def access_errors(self) -> list[str]:
        """Parts of the evidence that could not be read (unique, in discovery order)."""
        return []

    def sub_sources(self) -> list[tuple[str, "EvidenceSource"]]:
        """Further evidence trees inside this source (e.g. shadow copies), as (prefix, source)."""
        return []

    def close(self) -> None:
        pass

    def __enter__(self) -> "EvidenceSource":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
