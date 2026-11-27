"""Download the pinned SigmaHQ core rule set into investigation/resources/sigma/ (developer/build machines only)."""

from __future__ import annotations

import hashlib
import shutil
import ssl
import sys
import tempfile
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from investigation.core.rules_update import SIGMA_BUNDLED_SHA256, SIGMA_BUNDLED_TAG, SIGMA_BUNDLED_URL, update_sigma

DEST = Path(__file__).resolve().parents[1] / "investigation" / "resources" / "sigma"
STAMP = "SHA256"
OWNED = ("rules", "VERSION", STAMP)


def _tls_context() -> ssl.SSLContext:
    """certifi's CA bundle when available: a fresh Windows store often lacks the root GitHub chains to.
    Integrity comes from the pinned sha256 anyway."""
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def _present() -> bool:
    stamp = DEST / STAMP
    return (
        stamp.is_file()
        and stamp.read_text(encoding="utf-8").strip() == SIGMA_BUNDLED_SHA256
        and any((DEST / "rules").rglob("*.yml"))
    )


def main() -> int:
    DEST.mkdir(parents=True, exist_ok=True)
    if _present():
        print(f"{DEST} already holds SigmaHQ {SIGMA_BUNDLED_TAG} (verified)")
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        archive = tmp / "sigma_core.zip"
        with urllib.request.urlopen(SIGMA_BUNDLED_URL, timeout=120, context=_tls_context()) as resp:
            archive.write_bytes(resp.read())
        got = hashlib.sha256(archive.read_bytes()).hexdigest()
        if got != SIGMA_BUNDLED_SHA256:
            print(f"sha256 mismatch for sigma_core.zip: expected {SIGMA_BUNDLED_SHA256}, got {got}", file=sys.stderr)
            return 1
        staged = tmp / "set"
        try:
            update_sigma(dest=staged, zip_path=archive)
        except ValueError as exc:
            print(f"cannot extract sigma_core.zip: {exc}", file=sys.stderr)
            return 1
        for name in OWNED:
            target = DEST / name
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink(missing_ok=True)
        shutil.copytree(staged / "rules", DEST / "rules")
        (DEST / "VERSION").write_text(f"{SIGMA_BUNDLED_TAG}\n", encoding="utf-8")
        (DEST / STAMP).write_text(got + "\n", encoding="utf-8")
    print(f"{DEST} holds SigmaHQ {SIGMA_BUNDLED_TAG} ({got})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
