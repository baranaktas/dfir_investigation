"""Console output helper."""

from __future__ import annotations

import sys
import time
from typing import Callable

INTERVAL = 2.0


def say(line: str) -> None:
    """Console output must never break a collection (e.g. a cp1252 console and a non-Latin message)."""
    try:
        print(line)
    except Exception:
        try:
            enc = getattr(sys.stdout, "encoding", None) or "ascii"
            print(line.encode(enc, errors="replace").decode(enc, errors="replace"))
        except Exception:
            pass


class Throttle:
    """True at most once per interval: progress is printed as new lines, never more than ~1 per 2 s per step."""

    def __init__(self, interval: float | None = None, clock: Callable[[], float] = time.monotonic):
        self.interval = INTERVAL if interval is None else interval
        self.clock = clock
        self._last: float | None = None

    def ready(self) -> bool:
        now = self.clock()
        if self._last is None or now - self._last >= self.interval:
            self._last = now
            return True
        return False


def human_bytes(n: float) -> str:
    for unit, size in (("GB", 1000 ** 3), ("MB", 1000 ** 2), ("KB", 1000)):
        if n >= size:
            return f"{n / size:.1f} {unit}"
    return f"{int(n)} B"


def short_path(text: str, width: int = 50) -> str:
    return text if len(text) <= width else "..." + text[-(width - 3):]
