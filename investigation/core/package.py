"""Collection package: manifest with per-file hashes, and its verification."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from pathlib import Path
from typing import Any, Callable, Mapping

MANIFEST_NAME = "manifest.json"


class ManifestError(Exception):
    """manifest.json is present but cannot be used."""


LOG_NAME = "collection.log"
FORMAT_VERSION = 1


def hash_file(path: Path, algorithms: tuple[str, ...] = ("sha256",)) -> dict[str, str]:
    hashers = {a: hashlib.new(a) for a in algorithms}
    with open(path, "rb") as fh:
        while chunk := fh.read(1024 * 1024):
            for h in hashers.values():
                h.update(chunk)
    return {a: h.hexdigest() for a, h in hashers.items()}


UNVERIFIED_PREFIX = "not verified at analysis:"


def _nfc(path: str) -> str:
    """Compare names in one Unicode form: a package copied from Windows (NFC) to macOS can list as NFD."""
    return unicodedata.normalize("NFC", path)


def _package_files(root: Path) -> list[Path]:
    return sorted(
        p for p in root.rglob("*")
        if p.is_file() and p.relative_to(root).as_posix() not in (MANIFEST_NAME, LOG_NAME)
    )


def write_manifest(
    root: Path,
    info: Mapping[str, Any],
    extra_files: Mapping[str, Mapping[str, Any]] | None = None,
) -> Path:
    root = Path(root)
    extra = extra_files or {}
    path = root / MANIFEST_NAME
    interrupted: BaseException | None = None
    try:
        files = []
        for p in _package_files(root):
            rel = p.relative_to(root).as_posix()
            size = p.stat().st_size
            given = extra.get(rel, {})
            trusted = given.get("sha256") if given.get("size") == size else None
            entry: dict[str, Any] = {"path": rel, "size": size, "sha256": trusted or hash_file(p)["sha256"]}
            entry.update({k: v for k, v in given.items() if k not in ("size", "sha256")})
            files.append(entry)
        stored = {f["path"] for f in files}
        for rel, given in extra.items():
            same = given.get("same_as")
            if not same or rel in stored or same not in stored:
                continue
            target = next(f for f in files if f["path"] == same)
            entry = {"path": rel, "size": target["size"], "sha256": given.get("sha256") or target["sha256"]}
            entry.update({k: v for k, v in given.items() if k not in ("size", "sha256")})
            files.append(entry)
        files.sort(key=lambda f: f["path"])
        manifest = {"format_version": FORMAT_VERSION, **info, "files": files}
        text = json.dumps(manifest, indent=2, ensure_ascii=True)
    except BaseException as exc:
        if not isinstance(exc, Exception):
            interrupted = exc
        minimal = {"format_version": FORMAT_VERSION, **{k: v for k, v in info.items() if k != "warnings"},
                   "status": "partial",
                   "warnings": [*list(info.get("warnings") or []),
                                f"full manifest could not be written ({type(exc).__name__}: {exc}); file list omitted"],
                   "files": []}
        text = json.dumps(minimal, indent=2, ensure_ascii=True, default=str)
    path.write_text(text, encoding="utf-8")
    if interrupted is not None:
        raise interrupted
    return path


def _unsafe(rel: object, root: Path) -> bool:
    if not isinstance(rel, str) or not rel or rel.startswith(("/", "\\")) or ":" in rel:
        return True
    if ".." in rel.replace("\\", "/").split("/"):
        return True
    try:
        return not (root / rel).resolve().is_relative_to(root.resolve())
    except (OSError, RuntimeError, ValueError):
        return True


def dedup_problem(entry: Mapping[str, Any], by_path: Mapping[str, Any], root: Path) -> str | None:
    """Why an entry that points at another stored file (same_as) cannot be trusted, or None when it is sound."""
    rel, same = entry.get("path"), entry.get("same_as")
    target = by_path.get(same) if isinstance(same, str) else None
    if _unsafe(same, root) or target is None or "same_as" in target:
        return f"identical-copy entry points at a missing or invalid file: {rel} -> {same!r}"
    if target.get("sha256") != entry.get("sha256") or target.get("size") != entry.get("size"):
        return f"identical-copy entry does not match the file it points at: {rel} -> {same}"
    return None


LARGE_FILE = 1024 ** 3


def verify_manifest(root: Path, skip_images: bool = True,
                    progress: Callable[[str], None] = lambda msg: print(msg, flush=True)) -> list[str]:
    """Check every listed file. With skip_images, disk images (disk/*, entries carrying an md5) are not
    re-hashed: that can take hours; `investigation verify <package>` does the full check."""
    root = Path(root)
    try:
        manifest = json.loads((root / MANIFEST_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"cannot read {MANIFEST_NAME}: {exc}"]
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files", []), list):
        return [f"malformed {MANIFEST_NAME}: expected an object with a 'files' list"]
    problems: list[str] = []
    listed: set[str] = set()
    by_path = {e["path"]: e for e in manifest.get("files", []) if isinstance(e, dict) and isinstance(e.get("path"), str)}
    deduped = 0
    on_disk = {_nfc(q.relative_to(root).as_posix()): q for q in _package_files(root)}
    for entry in manifest.get("files", []):
        rel = entry.get("path") if isinstance(entry, dict) else None
        if _unsafe(rel, root):
            problems.append(f"unsafe or malformed manifest path ignored: {rel!r}")
            continue
        listed.add(_nfc(rel))
        p = on_disk.get(_nfc(rel), root / rel)
        if "same_as" in entry:
            bad = dedup_problem(entry, by_path, root)
            if bad:
                problems.append(bad)
            elif p.exists():
                problems.append(f"file present where an identical-copy entry was expected: {rel}")
            else:
                deduped += 1
            continue
        if not p.is_file():
            problems.append(f"missing file: {rel}")
        elif p.stat().st_size != entry.get("size"):
            problems.append(f"hash mismatch: {rel}")
        elif skip_images and "md5" in entry and rel.replace("\\", "/").startswith("disk/"):
            problems.append(f"{UNVERIFIED_PREFIX} {rel} (run 'investigation verify <package>')")
        else:
            if p.stat().st_size >= LARGE_FILE:
                progress(f"hashing {rel} ({p.stat().st_size / 1024 ** 3:.1f} GiB)...")
            if hash_file(p)["sha256"] != entry.get("sha256"):
                problems.append(f"hash mismatch: {rel}")
    for p in _package_files(root):
        rel = p.relative_to(root).as_posix()
        if _nfc(rel) not in listed:
            problems.append(f"not in manifest: {rel}")
    if deduped:
        progress(f"{deduped} shadow copy file(s) are identical to files/ copies and are stored once")
    return problems


def verify_zip(path: Path, progress: Callable[[str], None] = lambda msg: print(msg, flush=True)) -> list[str]:
    """Same check as verify_manifest, reading the members of a package zip without extracting it."""
    import zipfile

    path = Path(path)
    try:
        z = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        return [f"cannot open zip: {exc}"]
    with z:
        members = {i.filename.replace("\\", "/"): i for i in z.infolist() if not i.is_dir()}
        tops = {n.split("/", 1)[0] for n in members}
        prefix = "" if MANIFEST_NAME in members else (next(iter(tops)) + "/" if len(tops) == 1 else "")
        info = members.get(prefix + MANIFEST_NAME)
        if info is None:
            return [f"cannot find {MANIFEST_NAME} in the zip"]
        try:
            manifest = json.loads(z.read(info).decode("utf-8-sig"))
        except ValueError as exc:
            return [f"cannot read {MANIFEST_NAME}: {exc}"]
        if not isinstance(manifest, dict) or not isinstance(manifest.get("files", []), list):
            return [f"malformed {MANIFEST_NAME}: expected an object with a 'files' list"]
        fake_root = Path("/zip-root")
        by_path = {e["path"]: e for e in manifest["files"] if isinstance(e, dict) and isinstance(e.get("path"), str)}
        problems: list[str] = []
        listed: set[str] = set()
        deduped = 0
        for entry in manifest["files"]:
            rel = entry.get("path") if isinstance(entry, dict) else None
            if _unsafe(rel, fake_root):
                problems.append(f"unsafe or malformed manifest path ignored: {rel!r}")
                continue
            listed.add(_nfc(rel))
            member = members.get(prefix + rel)
            if "same_as" in entry:
                bad = dedup_problem(entry, by_path, fake_root)
                if bad:
                    problems.append(bad)
                elif member is not None:
                    problems.append(f"file present where an identical-copy entry was expected: {rel}")
                else:
                    deduped += 1
                continue
            if member is None:
                problems.append(f"missing file: {rel}")
            elif member.file_size != entry.get("size"):
                problems.append(f"hash mismatch: {rel}")
            else:
                if member.file_size >= LARGE_FILE:
                    progress(f"hashing {rel} ({member.file_size / 1024 ** 3:.1f} GiB)...")
                h = hashlib.sha256()
                with z.open(member) as fh:
                    while chunk := fh.read(1024 * 1024):
                        h.update(chunk)
                if h.hexdigest() != entry.get("sha256"):
                    problems.append(f"hash mismatch: {rel}")
        for name in members:
            rel = name[len(prefix):] if name.startswith(prefix) else name
            if rel not in (MANIFEST_NAME, LOG_NAME) and _nfc(rel) not in listed:
                problems.append(f"not in manifest: {rel}")
    if deduped:
        progress(f"{deduped} shadow copy file(s) are identical to files/ copies and are stored once")
    return problems
