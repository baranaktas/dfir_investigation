"""Raw file collection (KAPE layout): NTFS volume via dissect.ntfs, or plain OS access as a fallback."""

from __future__ import annotations

import fnmatch
import hashlib
import logging
import ntpath
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterator, Protocol

import yaml
from dissect.util.stream import AlignedStream

from investigation.core.console import Throttle, human_bytes, say as _say, short_path
from investigation.core.module import CollectorModule, ModuleMeta, ModuleType
from investigation.core.registry import register
from investigation.core.requirements import Context
from investigation.modules.collectors.volumes import device_length as _volume_size
from investigation.modules.collectors.volumes import list_volumes
from investigation.core.frozen import resource

log = logging.getLogger("investigation.collect")

TARGETS_FILE = resource("artifacts/collect_targets.yaml")
CHUNK = 1 << 20


class Reader(Protocol):
    def listdir(self, path: str) -> list[str]: ...
    def is_dir(self, path: str) -> bool: ...
    def open(self, path: str) -> BinaryIO: ...
    def stat(self, path: str) -> tuple[int, datetime | None]: ...


def _under(path: str, exclude: str | None) -> bool:
    if not exclude:
        return False
    p, e = path.strip("/").lower(), exclude.strip("/").lower()
    return p == e or p.startswith(e + "/")


class OsReader:
    raw = False

    def __init__(self, root: Path, exclude: Path | None = None):
        self.root = Path(root)
        self.exclude = Path(os.path.abspath(exclude)) if exclude else None

    def _p(self, path: str) -> Path:
        return self.root / path

    def _excluded(self, p: Path) -> bool:
        if self.exclude is None:
            return False
        a = Path(os.path.abspath(p))
        return a == self.exclude or self.exclude in a.parents

    @staticmethod
    def _link(p: Path) -> bool:
        if p.is_symlink():
            return True
        try:
            return bool(os.lstat(p).st_file_attributes & 0x400)
        except (AttributeError, OSError):
            return False

    def listdir(self, path: str) -> list[str]:
        base = self._p(path)
        return [e.name for e in base.iterdir() if not self._excluded(e) and not self._link(e)]

    def is_dir(self, path: str) -> bool:
        p = self._p(path)
        return p.is_dir() and not self._link(p) and not self._excluded(p)

    def open(self, path: str) -> BinaryIO:
        p = self._p(path)
        if self._link(p) or self._excluded(p):
            raise PermissionError(f"refusing link/excluded path {path}")
        return open(p, "rb")

    def stat(self, path: str) -> tuple[int, datetime | None]:
        st = self._p(path).stat()
        return st.st_size, datetime.fromtimestamp(st.st_mtime, timezone.utc)


class NtfsReader:
    raw = True

    def __init__(self, volume: BinaryIO, exclude: str | None = None):
        from dissect.ntfs import NTFS

        self.volume = volume
        self.ntfs = NTFS(volume)
        self.exclude = exclude

    def close(self) -> None:
        self.volume.close()

    def sparse_prefix(self, path: str) -> int:
        """Bytes of leading sparse (never allocated) runs of the stream; 0 if none."""
        rec, stream = self._rec(path)
        try:
            runs = rec.dataruns(stream)
        except Exception:
            return 0
        clusters = 0
        for offset, count in runs:
            if offset is not None:
                break
            clusters += count
        return min(clusters * self.ntfs.cluster_size, rec.size(stream))

    def _rec(self, path: str):
        base, _, stream = path.partition(":")
        if _under(base, self.exclude):
            raise PermissionError(f"excluded path {path}")
        return self.ntfs.mft.get(base), stream

    def listdir(self, path: str) -> list[str]:
        rec, _ = self._rec(path)
        return [n for n in rec.listdir(ignore_dos=True)
                if not _under(f"{path}/{n}", self.exclude)]

    def is_dir(self, path: str) -> bool:
        rec, _ = self._rec(path)
        return rec.is_dir() and not (rec.is_symlink() or rec.is_mount_point())

    def open(self, path: str) -> BinaryIO:
        rec, stream = self._rec(path)
        return rec.open(stream)

    def stat(self, path: str) -> tuple[int, datetime | None]:
        rec, stream = self._rec(path)
        try:
            mtime = rec.attributes.STANDARD_INFORMATION.last_modification_time
            mtime = mtime if mtime.tzinfo else mtime.replace(tzinfo=timezone.utc)
        except Exception:
            mtime = None
        return rec.size(stream), mtime


class AlignedVolume(AlignedStream):
    """Read-only view of a raw volume handle that only issues sector-aligned reads."""

    def __init__(self, fh: BinaryIO, size: int | None = None, align: int = 4096):
        super().__init__(size, align)
        self._fh = fh

    def _read(self, offset: int, length: int) -> bytes:
        self._fh.seek(offset)
        return self._fh.read(length)

    def close(self) -> None:
        self._fh.close()
        super().close()


def open_volume(letter: str, fallback_size: int = 0) -> AlignedVolume:
    raw = open(rf"\\.\{letter}:", "rb", buffering=0)
    return AlignedVolume(raw, _volume_size(raw) or fallback_size or None)


def open_system_volume() -> NtfsReader:
    letter = os.environ.get("SystemDrive", "C:").rstrip(":\\/").upper()
    vol = open_volume(letter)
    try:
        return NtfsReader(vol)
    except Exception:
        vol.close()
        raise


def expand(reader: Reader, pattern: str, on_error=None) -> Iterator[str]:
    """Yield real-cased paths matching a "/"-separated, per-segment case-insensitive glob."""
    def walk(prefix: str, segs: list[str]) -> Iterator[str]:
        if not segs:
            yield prefix
            return
        seg, rest = segs[0], segs[1:]
        base, colon, stream = seg.partition(":")
        try:
            names = reader.listdir(prefix)
        except Exception as exc:
            if on_error and not isinstance(exc, (FileNotFoundError, NotADirectoryError)):
                on_error(prefix, exc)
            return
        for name in names:
            if fnmatch.fnmatchcase(name.lower(), base.lower()):
                nxt = f"{prefix}/{name}" if prefix else name
                try:
                    if rest and not reader.is_dir(nxt):
                        continue
                except Exception as exc:
                    if on_error:
                        on_error(nxt, exc)
                    continue
                yield from walk(nxt + colon + stream, rest)

    yield from walk("", pattern.split("/"))


def load_targets() -> list[dict]:
    return yaml.safe_load(TARGETS_FILE.read_text(encoding="utf-8")) or []


def _iso(dt: datetime | None) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds") if dt else ""


def win_long_path(p: Path, os_name: str | None = None) -> str:
    """Absolute extended-length (\\\\?\\) form of p on Windows so reserved names, trailing dots/spaces and
    paths over MAX_PATH are taken literally. Identity (str) elsewhere."""
    text = str(p)
    if (os_name or os.name) != "nt":
        return text
    if text.startswith("\\\\?\\") or text.startswith("\\\\.\\"):
        return text
    text = ntpath.abspath(text)
    if text.startswith("\\\\"):
        return "\\\\?\\UNC\\" + text[2:]
    return "\\\\?\\" + text


_RESERVED = frozenset({"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                       *(f"LPT{i}" for i in range(1, 10))})


def safe_component(name: str) -> str:
    """Encode what Win32 would mangle: a reserved device name (with or without extension), trailing dots/spaces
    and backslashes (a crafted NTFS name such as '..\\..\\x' must stay one component)."""
    if not name:
        return name
    name = name.replace("\\", "%5C")
    stem = name.split(".", 1)[0].rstrip(" ").upper()
    if stem in _RESERVED:
        name = f"%{ord(name[0]):02X}" + name[1:]
    stripped = name.rstrip(". ")
    tail = name[len(stripped):]
    return stripped + "".join(f"%{ord(c):02X}" for c in tail)


def safe_key(rel: str) -> str:
    return "/".join(safe_component(c) for c in rel.replace(":", "%3A").split("/"))


def inside(root: Path, dest: Path) -> bool:
    """True if dest, normalised the way Windows will resolve it, stays under root."""
    base = os.path.normcase(os.path.abspath(root))
    target = os.path.normcase(os.path.abspath(dest))
    return target.startswith(base.rstrip(os.sep) + os.sep)


def _copy(reader: Reader, rel: str, dest: Path, skip: int = 0) -> str:
    os.makedirs(win_long_path(dest.parent), exist_ok=True)
    h = hashlib.sha256()
    try:
        with reader.open(rel) as src, open(win_long_path(dest), "wb") as dst:
            if skip:
                src.seek(skip)
            for chunk in iter(lambda: src.read(CHUNK), b""):
                h.update(chunk)
                dst.write(chunk)
    except BaseException:
        try:
            os.unlink(win_long_path(dest))
        except OSError:
            pass
        raise
    return h.hexdigest()


def _identical_copy(root: Path, extra: dict, live_key: str, key: str, digest: str) -> str | None:
    """live_key if that file was collected in this run and holds exactly the bytes just written to key."""
    live = extra.get(live_key)
    if not live or "same_as" in live or live.get("source_sha256") != digest:
        return None
    try:
        if os.path.getsize(win_long_path(root / live_key)) != os.path.getsize(win_long_path(root / key)):
            return None
    except OSError:
        return None
    return live_key


def _discard(root: Path, key: str) -> None:
    """Delete a just written duplicate and the directories it leaves empty."""
    try:
        os.unlink(win_long_path(root / key))
    except OSError:
        return
    parent = (root / key).parent
    while parent != root and parent.is_relative_to(root):
        try:
            os.rmdir(win_long_path(parent))
        except OSError:
            break
        parent = parent.parent


def _make_reader(letter: str, out_dir: Path, warnings: list[str]) -> Reader | None:
    exclude = None
    resolved = Path(os.path.abspath(out_dir))
    if resolved.drive and resolved.drive.rstrip(":").upper() == letter:
        exclude = "/".join(resolved.parts[1:])
    vol = next((v for v in list_volumes() if v.letter.rstrip(":").upper() == letter), None)
    if vol is None:
        msg = f"drive {letter} not found, skipped"
        log.warning(msg)
        warnings.append(msg)
        return None
    if vol.fstype.upper() == "NTFS":
        handle = None
        try:
            handle = open_volume(letter, vol.size)
            return NtfsReader(handle, exclude)
        except Exception as exc:
            if handle is not None:
                handle.close()
            msg = (f"raw NTFS access failed on {letter}: {type(exc).__name__}: {exc}; "
                   "falling back to OS access, locked files skipped")
            log.warning(msg)
            warnings.append(msg)
    return OsReader(Path(f"{letter}:\\"), out_dir)


@register
class FilesCollector(CollectorModule):
    meta = ModuleMeta(
        name="files_raw",
        description="Copy forensic files from raw NTFS (KAPE layout)",
        type=ModuleType.COLLECTOR,
        platforms=("windows",),
        category="files",
        priority=100,
    )

    def collect(self, ctx: Context, out_dir: Path) -> int:
        opts = ctx.options
        extra = opts.get("extra_files", {})
        warnings = opts.get("warnings", [])
        root = Path(opts.get("package_root", out_dir))
        readers = opts.get("files_readers")
        letters = list(readers) if readers else [
            str(d).rstrip(":\\/").upper() for d in (
                opts.get("drives") or [os.environ.get("SystemDrive", "C:")])]
        targets = load_targets()
        copied = 0

        def problem(path: str, exc: Exception) -> None:
            msg = f"{letter}:{path} skipped: {type(exc).__name__}: {exc}"
            log.warning(msg)
            warnings.append(msg)

        for letter in letters:
            reader = readers[letter] if readers else _make_reader(letter, out_dir, warnings)
            if reader is None:
                continue
            stats: dict = {}
            throttle = Throttle()
            try:
                for target in targets:
                    if target.get("raw_only") and not getattr(reader, "raw", False):
                        log.info("%s:%s skipped: needs raw NTFS access", letter, target["name"])
                        continue
                    for pattern in target["paths"]:
                        try:
                            for rel in expand(reader, pattern, problem):
                                copied += self._one(reader, letter, rel, root, extra, stats=stats)
                                if throttle.ready():
                                    _say(f"[files] {letter}: {stats.get('files', 0)} files, "
                                         f"{human_bytes(stats.get('bytes', 0))}  {short_path(rel)}")
                        except Exception as exc:
                            problem(pattern, exc)
                _say(f"[files] {letter}: {stats.get('files', 0)} files, {human_bytes(stats.get('bytes', 0))}")
            finally:
                if not readers and hasattr(reader, "close"):
                    reader.close()
        return copied

    @staticmethod
    def _one(reader: Reader, letter: str, rel: str, root: Path, extra: dict, prefix: str = "files",
             dedupe_against: str | None = None, stats: dict | None = None) -> int:
        try:
            if reader.is_dir(rel.partition(":")[0]):
                return 0
            size, mtime = reader.stat(rel)
            key = f"{prefix}/{letter}/{safe_key(rel)}"
            skip = getattr(reader, "sparse_prefix", lambda _p: 0)(rel)
            if not inside(root, root / key):
                raise ValueError(f"destination escapes the package: {key!r}")
            digest = _copy(reader, rel, root / key, skip)
        except Exception as exc:
            log.warning("%s:%s unreadable, skipped: %s", letter, rel, exc)
            return 0
        extra[key] = {"source_path": f"{letter}:\\" + rel.replace("/", "\\"),
                      "source_mtime_utc": _iso(mtime), "source_sha256": digest}
        if dedupe_against:
            same = _identical_copy(root, extra, f"{dedupe_against}/{letter}/{safe_key(rel)}", key, digest)
            if same:
                _discard(root, key)
                extra[key].update({"same_as": same, "sha256": digest})
        if key != f"{prefix}/{letter}/{rel.replace(':', '%3A')}":
            extra[key]["original_name"] = rel
        if skip:
            extra[key]["sparse_prefix_bytes"] = skip
        if stats is not None:
            stats["files"] = stats.get("files", 0) + 1
            stats["bytes"] = stats.get("bytes", 0) + max(size - skip, 0)
            stats["unchanged"] = stats.get("unchanged", 0) + ("same_as" in extra[key])
        return 1
