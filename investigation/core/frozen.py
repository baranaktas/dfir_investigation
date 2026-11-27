"""Frozen-safe (PyInstaller) lookup of package data."""

from __future__ import annotations

import sys
from pathlib import Path


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def resource(rel: str) -> Path:
    """Path of a packaged data file/dir, relative to the `investigation` package."""
    if is_frozen() and getattr(sys, "_MEIPASS", None):
        base = Path(sys._MEIPASS) / "investigation"
    else:
        import investigation

        base = Path(investigation.__file__).resolve().parent
    return base / rel if rel else base
