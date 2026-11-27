"""Download the pinned WinPmem binary into investigation/resources/winpmem/ (developer/build machines only)."""

from __future__ import annotations

import hashlib
import os
import ssl
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from investigation.modules.collectors.memory import WINPMEM_NAME, WINPMEM_SHA256, WINPMEM_URL

DEST = Path(__file__).resolve().parents[1] / "investigation" / "resources" / "winpmem"


def _tls_context() -> ssl.SSLContext:
    """certifi's CA bundle when available: a fresh Windows store often lacks the root GitHub chains to, because
    Windows only fetches roots on demand for its own HTTP stack. Integrity comes from the pinned sha256 anyway."""
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def main() -> int:
    DEST.mkdir(parents=True, exist_ok=True)
    target = DEST / WINPMEM_NAME
    part = DEST / (WINPMEM_NAME + ".part")
    if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == WINPMEM_SHA256:
        print(f"{target} already present and verified")
        return 0
    try:
        with urllib.request.urlopen(WINPMEM_URL, timeout=60, context=_tls_context()) as resp:
            part.write_bytes(resp.read())
        got = hashlib.sha256(part.read_bytes()).hexdigest()
        if got != WINPMEM_SHA256:
            print(f"sha256 mismatch for {WINPMEM_NAME}: expected {WINPMEM_SHA256}, got {got}", file=sys.stderr)
            return 1
        os.replace(part, target)
    finally:
        part.unlink(missing_ok=True)
    print(f"{target} verified ({got})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
