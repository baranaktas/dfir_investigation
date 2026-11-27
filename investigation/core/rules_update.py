"""Download and safely install the SigmaHQ Windows rule set."""

from __future__ import annotations

import shutil
import tempfile
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Callable, NamedTuple

from investigation import __version__
from investigation.core.frozen import resource
from investigation.core.registry import investigation_home

SIGMA_URL = "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core.zip"
SIGMA_BUNDLED_TAG = "r2026-07-01"
SIGMA_BUNDLED_URL = f"https://github.com/SigmaHQ/sigma/releases/download/{SIGMA_BUNDLED_TAG}/sigma_core.zip"
SIGMA_BUNDLED_SHA256 = "45ccbd62cbf0d7ccca6f44eaa010f86bb24f082b5411c5e22c71907e7770ee46"
MAX_DOWNLOAD = 200 * 1024 * 1024
MAX_MEMBER = 1024 * 1024
MAX_TOTAL = 100 * 1024 * 1024
TIMEOUT = 60


def sigma_root() -> Path:
    return investigation_home() / "rules" / "sigma"


def sigmahq_dir() -> Path:
    return sigma_root() / "sigmahq"


def sigma_rules_present() -> bool:
    root = sigma_root()
    return root.is_dir() and any(p.suffix in (".yml", ".yaml") for p in root.rglob("*"))


def _has_rules(root: Path) -> bool:
    return root.is_dir() and any(p.suffix in (".yml", ".yaml") for p in root.rglob("*"))


def bundled_sigma_dir() -> Path:
    return resource("resources/sigma")


def bundled_sigma_present() -> bool:
    return _has_rules(bundled_sigma_dir())


def bundled_sigma_tag() -> str:
    version = bundled_sigma_dir() / "VERSION"
    try:
        first = version.read_text(encoding="utf-8").splitlines()[0].strip()
    except (OSError, IndexError):
        first = ""
    return first or SIGMA_BUNDLED_TAG


class SigmaSources(NamedTuple):
    paths: list[Path]
    label: str
    kind: str


def sigma_sources() -> SigmaSources:
    """Rule folders to load. A SigmaHQ set downloaded by `rules update` replaces the bundled one; the user's
    own rules in the same folder are always loaded."""
    user = sigma_root()
    if _has_rules(sigmahq_dir()):
        version = sigmahq_dir() / "VERSION"
        try:
            release = version.read_text(encoding="utf-8").splitlines()[0].strip()
        except (OSError, IndexError):
            release = ""
        return SigmaSources([user], f"downloaded SigmaHQ {release or 'rules'} in {user}", "downloaded")
    if bundled_sigma_present():
        return SigmaSources([bundled_sigma_dir(), user], f"bundled SigmaHQ {bundled_sigma_tag()}", "bundled")
    if _has_rules(user):
        return SigmaSources([user], f"your rules in {user}", "custom")
    return SigmaSources([user], f"no rules in {user}", "none")


def _download(url: str, dest: Path) -> str:
    """Download to `dest`; returns the final URL (release name is in it). Generic User-Agent only."""
    req = urllib.request.Request(url, headers={"User-Agent": f"investigation/{__version__}"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp, dest.open("wb") as out:
        total = 0
        while chunk := resp.read(1 << 16):
            total += len(chunk)
            if total > MAX_DOWNLOAD:
                raise ValueError("download larger than 200 MiB - refusing")
            out.write(chunk)
        return resp.geturl()


def _safe_member(name: str) -> PurePosixPath | None:
    """Only rules/windows/**.yml with no absolute path, drive, backslash or '..'."""
    if name.startswith("/") or "\\" in name or ":" in name:
        return None
    p = PurePosixPath(name)
    if ".." in p.parts or not p.parts:
        return None
    parts = p.parts[1:] if p.parts[0] not in ("rules",) and len(p.parts) > 1 and p.parts[1] == "rules" else p.parts
    if len(parts) < 3 or parts[0] != "rules" or parts[1] != "windows":
        return None
    if p.suffix.casefold() not in (".yml", ".yaml"):
        return None
    return PurePosixPath(*parts)


def update_sigma(
    dest: Path | None = None,
    url: str = SIGMA_URL,
    zip_path: Path | None = None,
    fetch: Callable[[str, Path], str] = _download,
) -> dict[str, int]:
    dest = Path(dest) if dest else sigmahq_dir()
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=dest.parent) as tmp:
        tmp = Path(tmp)
        release = ""
        if zip_path is None:
            zip_path = tmp / "sigma.zip"
            final_url = fetch(url, zip_path) or url
            release = final_url.rstrip("/").split("/")[-2] if "/download/" in final_url else ""
        staging = tmp / "staging"
        staging.mkdir()
        written = skipped = total = 0
        try:
            with zipfile.ZipFile(zip_path) as z:
                for info in z.infolist():
                    if info.is_dir():
                        continue
                    if info.filename.rsplit("/", 1)[-1] == "version.txt" and info.file_size < 1024:
                        release = release or z.read(info).decode("utf-8", "replace").strip()
                        continue
                    rel = _safe_member(info.filename)
                    if rel is None or info.file_size > MAX_MEMBER:
                        skipped += 1
                        continue
                    total += info.file_size
                    if total > MAX_TOTAL:
                        raise ValueError("archive expands beyond 100 MiB - refusing")
                    data = z.read(info)
                    if len(data) > MAX_MEMBER:
                        skipped += 1
                        continue
                    out = staging / rel
                    if not out.resolve().is_relative_to(staging.resolve()):
                        skipped += 1
                        continue
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_bytes(data)
                    written += 1
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, OSError) as exc:
            raise ValueError(f"cannot read the rules archive: {exc}") from None
        if written == 0:
            raise ValueError("archive contained no Windows Sigma rules")
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        (staging / "VERSION").write_text(f"{release or 'unknown release'}\nfetched {stamp}\n", encoding="utf-8")
        old = tmp / "old"
        if dest.exists():
            dest.rename(old)
        staging.rename(dest)
    return {"rules": written, "skipped": skipped}
