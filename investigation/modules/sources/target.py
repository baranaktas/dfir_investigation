"""Disk images, VM disks, triage collections and Windows system trees via Fox-IT dissect.target."""

from __future__ import annotations

import builtins
import io
import logging
import os
import re
import struct
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, Iterator

from investigation.core.module import ModuleMeta, ModuleType, SourceModule
from investigation.core.registry import register
from investigation.core.requirements import PythonPackage
from investigation.core.source import EvidenceSource, glob_to_regex
from investigation.core.frozen import resource

if TYPE_CHECKING:
    from dissect.target import Target

log = logging.getLogger("investigation")

DISSECT_TARGET = PythonPackage("dissect.target", "dissect.target", min_version="3.20")

IMAGE_SUFFIXES = (
    ".e01", ".ex01", ".s01", ".raw", ".dd", ".img", ".001", ".vmdk", ".vhd", ".vhdx", ".qcow2", ".vdi",
    ".zip", ".tar", ".tgz", ".gz",
)
_WILDCARDS = set("*?[")


def _allowed_host_paths(evidence: Path):
    """Host files dissect may open while loading `evidence`: everything inside an evidence directory, or,
    for a file, the file itself and same-directory siblings sharing its stem (E01 segments, VMDK extents)."""
    evidence = Path(evidence).resolve()
    roots = [Path(p).resolve() for p in {sys.prefix, sys.base_prefix, sys.exec_prefix} if p]
    roots.append(resource("").resolve())
    own_files: set[Path] = set()
    if getattr(sys, "frozen", False):
        if getattr(sys, "_MEIPASS", None):
            roots.append(Path(sys._MEIPASS).resolve())
        own_files.add(Path(sys.executable).resolve())
    stem = evidence.name.split(".", 1)[0] if not evidence.name.startswith(".") else ""
    sibling = re.compile(
        re.escape(stem)
        + r"(?:\.(?:e|ex|s|l|lx)[0-9a-z]{2}|\.\d{3}|(?:-s\d{3}|-f\d{3}|-flat|-delta|-sesparse|-\d{6})\.vmdk)\Z",
        re.IGNORECASE | re.ASCII,
    ) if stem else None

    def allowed(p: Path) -> bool:
        if p in own_files or any(p.is_relative_to(r) for r in roots):
            return True
        if evidence.is_dir():
            return p == evidence or p.is_relative_to(evidence)
        if p == evidence:
            return True
        return sibling is not None and p.parent == evidence.parent and bool(sibling.match(p.name))

    return allowed


@contextmanager
def host_file_jail(evidence: Path):
    """While dissect loads evidence, refuse every Python-level open() of a host file outside the evidence.

    Covers every container quirk at once (VMDK descriptors/parents, QCOW2 backing and data files, VHDX
    parents, ...): whatever the format says, the file cannot be opened. Not thread-safe - the pipeline is
    single-threaded."""
    allowed = _allowed_host_paths(evidence)
    original = io.open

    def guarded(file, *args, **kwargs):
        if isinstance(file, (str, bytes, os.PathLike)):
            try:
                resolved = Path(os.fsdecode(file)).resolve()
            except (OSError, RuntimeError, ValueError):
                raise PermissionError(f"refusing to open unresolvable path while loading evidence: {file!r}")
            if not allowed(resolved):
                raise PermissionError(f"evidence tried to make us open a host file outside it: {resolved}")
        return original(file, *args, **kwargs)

    io.open = builtins.open = guarded
    try:
        yield
    finally:
        io.open = builtins.open = original


def _ads_kape_loader():
    """KapeLoader that also finds the $J / $SDS streams of our own packages ('%3A'-encoded ADS names)."""
    from dissect.target.loaders import kape
    from dissect.target.loaders.dir import find_and_map_dirs, find_dirs
    from dissect.target.plugin import OperatingSystem

    usn = [*kape.USNJRNL_PATHS, "$Extend/$UsnJrnl%3A$J"]
    sds = ["$Secure_$SDS", "$Secure%3A$SDS"]

    class AdsKapeLoader(kape.KapeLoader):
        @staticmethod
        def detect(path: Path) -> bool:
            if not path.is_dir():
                return False
            os_type, dirs = find_dirs(path)
            return os_type == OperatingSystem.WINDOWS and any(d.joinpath(p).exists() for d in dirs for p in usn)

        def map(self, target) -> None:
            find_and_map_dirs(target, self.absolute_path, sds_path=sds, usnjrnl_path=usn)

    return AdsKapeLoader


def open_target(path: Path) -> "Target":
    """Open evidence with dissect.target (module-level so tests can substitute it).

    Directories are always mapped with the plain directory (or KAPE) loader - never auto-detected - so
    VM configuration files inside them cannot make dissect open disks elsewhere on the host."""
    from dissect.target import Target

    path = Path(path)
    if path.is_dir():
        from dissect.target.loaders.dir import DirLoader
        KapeLoader = _ads_kape_loader()

        loader_cls = KapeLoader if KapeLoader.detect(path) else DirLoader
        with host_file_jail(path):
            return Target._load(path, loader_cls(path), apply=True)
    with host_file_jail(path):
        return Target.open(path)


def is_link(p: Path) -> bool:
    """Symlink, or (Python < 3.12 has no is_junction) a Windows reparse point such as a junction."""
    if p.is_symlink():
        return True
    try:
        return bool(os.lstat(p).st_file_attributes & 0x400)
    except (AttributeError, OSError):
        return False


def check_directory_containment(root: Path, limit: int = 20) -> None:
    """Refuse evidence directories containing symlinks that point outside the evidence:
    dissect plugins would follow them and copy host files into the report."""
    root = Path(root).resolve()
    escaping: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            p = Path(dirpath) / name
            if is_link(p):
                try:
                    target = p.resolve()
                except (OSError, RuntimeError):
                    escaping.append(p.relative_to(root).as_posix())
                    continue
                if not target.is_relative_to(root):
                    escaping.append(p.relative_to(root).as_posix())
                    if len(escaping) >= limit:
                        break
    if escaping:
        raise ValueError(
            "evidence directory contains symlinks pointing outside it (refusing to follow them): "
            + ", ".join(escaping)
        )


_EXTENT = re.compile(r'^\s*(?:RW|RDONLY|NOACCESS)\s+\d+\s+\w+\s+"([^"]+)"', re.MULTILINE)
MAX_DESCRIPTOR = 1024 * 1024
SECTOR = 512


_PARENT_CID = re.compile(r'^\s*parentCID\s*=\s*"?([0-9a-fA-F]+)', re.MULTILINE)
MAX_DEPTH = 4


def _check_descriptor(text: str, base: Path, depth: int, seen: set[Path]) -> None:
    cid = _PARENT_CID.search(text)
    if "parentfilenamehint" in text.casefold() or (cid and cid.group(1).casefold() != "ffffffff"):
        raise ValueError("child/delta VMDK disks are not supported: they reference a parent disk by path")
    for ref in _EXTENT.findall(text):
        resolved = (base / ref).resolve()
        if Path(ref).is_absolute() or "\\" in ref[:2] or not resolved.is_relative_to(base):
            raise ValueError(f"disk descriptor references a file outside the evidence folder: {ref}")
        if resolved.is_file():
            _check(resolved, depth + 1, seen)


def _check_vhdx_parent(path: Path) -> None:
    import dissect.hypervisor.disk.vhdx as vhdx

    captured: list[dict] = []
    original = vhdx.open_parent
    vhdx.open_parent = lambda p, locator: captured.append(dict(locator))
    try:
        with path.open("rb") as fh:
            disk = vhdx.VHDX(fh)
            has_parent = bool(getattr(disk, "has_parent", False))
    except Exception as exc:
        raise ValueError(f"cannot verify VHDX {path.name}: {type(exc).__name__}: {exc}") from None
    finally:
        vhdx.open_parent = original
    if has_parent and not captured:
        captured.append({"note": "has_parent flag set"})
    if captured:
        raise ValueError(f"VHDX differencing disks are not supported: they reference a parent disk ({captured[0]})")


def check_disk_references(path: Path) -> None:
    """Fail closed on disk formats that can make dissect open other host files:
    VMDK descriptors (text or embedded) and their extents, child/delta VMDKs, COWD, and VHD/VHDX
    differencing disks. Detection is by content, not by file name; extents are checked recursively."""
    _check(Path(path), 0, set())


def _check(path: Path, depth: int, seen: set[Path]) -> None:
    real = path.resolve()
    if real in seen:
        return
    seen.add(real)
    if depth > MAX_DEPTH:
        raise ValueError(f"disk reference chain deeper than {MAX_DEPTH} levels: {path}")
    base = path.parent.resolve()
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            head = fh.read(SECTOR * 4)
            if head[:4] == b"# Di" or head.lstrip().startswith(b"# Disk DescriptorFile"):
                if size > MAX_DESCRIPTOR:
                    raise ValueError(f"VMDK descriptor file too large to verify ({size} bytes)")
                fh.seek(0)
                _check_descriptor(fh.read().decode("utf-8", "replace"), base, depth, seen)
            elif head[:4] == b"KDMV":
                desc_off, desc_size = struct.unpack_from("<QQ", head, 28)
                if desc_size:
                    if desc_size * SECTOR > MAX_DESCRIPTOR:
                        raise ValueError("embedded VMDK descriptor too large to verify")
                    fh.seek(desc_off * SECTOR)
                    text = fh.read(desc_size * SECTOR).split(b"\0", 1)[0].decode("utf-8", "replace")
                    _check_descriptor(text, base, depth, seen)
            elif head[:4] == b"COWD":
                raise ValueError("COWD (ESX sparse) disks are not supported: they reference parent disks by path")
            elif head[:4] == b"QFI\xfb":
                backing_offset = struct.unpack_from(">Q", head, 8)[0]
                version = struct.unpack_from(">I", head, 4)[0]
                incompatible = struct.unpack_from(">Q", head, 72)[0] if version >= 3 else 0
                if backing_offset:
                    raise ValueError("QCOW2 images with a backing file are not supported: merge the chain first")
                if incompatible & 0x4:
                    raise ValueError("QCOW2 images with an external data file are not supported")
            elif head[:8] == b"vhdxfile":
                _check_vhdx_parent(path)
            if size >= SECTOR:
                fh.seek(size - SECTOR)
                footer = fh.read(SECTOR)
                for candidate in (footer, head[:SECTOR]):
                    if candidate[:8] == b"conectix" and struct.unpack_from(">I", candidate, 60)[0] == 4:
                        raise ValueError("VHD differencing disks are not supported: they reference a parent disk")
    except OSError as exc:
        raise ValueError(f"cannot verify evidence file {path}: {exc}") from None


def _has_dir_ci(root: Path, *parts: str) -> bool:
    """Case-insensitive check that root/parts... is a directory."""
    current = root
    for part in parts:
        try:
            match = next((c for c in current.iterdir() if c.is_dir() and c.name.casefold() == part), None)
        except OSError:
            return False
        if match is None:
            return False
        current = match
    return True


class TargetEvidence(EvidenceSource):
    def __init__(self, target: "Target"):
        self.target = target
        self.is_system = getattr(target, "os", None) == "windows"
        self.root = "sysvol" if self.is_system else "/"
        try:
            self.name = str(target.hostname or target.path.name)
        except Exception:
            self.name = str(getattr(target, "path", "target"))
        self._errors: dict[str, None] = {}

    def _path(self, rel: str):
        rel = rel.strip("/")
        return self.target.fs.path(f"{self.root.rstrip('/')}/{rel}" if rel else self.root)

    def _walk(self, start_rel: str) -> Iterator[str]:
        stack = [start_rel.strip("/")]
        while stack:
            rel = stack.pop()
            try:
                entries = sorted(self._path(rel).iterdir(), key=lambda p: p.name, reverse=True)
            except Exception as exc:
                self._errors[f"cannot read {rel or '/'}: {exc}"] = None
                continue
            for entry in entries:
                child = f"{rel}/{entry.name}" if rel else entry.name
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir():
                        stack.append(child)
                    elif entry.is_file():
                        yield child
                except Exception as exc:
                    self._errors[f"cannot stat {child}: {exc}"] = None

    def iter_files(self) -> Iterator[str]:
        yield from self._walk("")

    def _resolve_prefix(self, parts: list[str]) -> str | None:
        """Resolve literal leading path segments case-insensitively; return the real relative path."""
        rel = ""
        for part in parts:
            try:
                match = next(
                    (c.name for c in self._path(rel).iterdir() if c.name.casefold() == part.casefold()), None
                )
            except Exception:
                return None
            if match is None:
                return None
            rel = f"{rel}/{match}" if rel else match
        return rel

    def glob(self, pattern: str) -> Iterator[str]:
        parts = pattern.strip("/").split("/")
        literal: list[str] = []
        for part in parts[:-1]:
            if _WILDCARDS & set(part):
                break
            literal.append(part)
        start = self._resolve_prefix(literal)
        if start is None:
            return
        rx = glob_to_regex(pattern.strip("/"))
        for path in self._walk(start):
            if rx.match(path):
                yield path

    def open(self, path: str) -> BinaryIO:
        if ".." in path.split("/"):
            raise ValueError(f"path escapes evidence root: {path}")
        return self._path(path).open("rb")

    def access_errors(self) -> list[str]:
        return list(self._errors)

    def stat(self, path: str):
        from datetime import datetime, timezone

        try:
            st = self._path(path).stat()
        except Exception:
            return None, None
        mtime = st.st_mtime
        return st.st_size, (datetime.fromtimestamp(mtime, timezone.utc) if mtime else None)

    def system_info(self) -> dict[str, str]:
        info: dict[str, str] = {}

        def put(key: str, getter) -> None:
            try:
                value: Any = getter()
            except Exception:
                return
            if value is None or value == "" or value == []:
                return
            if isinstance(value, (list, tuple, set)):
                value = ", ".join(str(v) for v in value)
            info[key] = str(value)

        t = self.target
        put("hostname", lambda: t.hostname)
        put("os", lambda: t.os)
        put("version", lambda: t.version)
        put("domain", lambda: t.domain)
        put("timezone", lambda: t.timezone)
        put("install_date", lambda: t.install_date)
        put("ips", lambda: t.ips)
        put("users", lambda: sorted({u.name for u in t.users() if getattr(u, "name", None)}))
        return info

    def close(self) -> None:
        try:
            self.target.close()
        except Exception:
            pass


@register
class TargetSource(SourceModule):
    meta = ModuleMeta(
        name="target",
        description="Disk images (E01/raw/dd), VM disks (VMDK/VHD/VHDX/QCOW2), KAPE/zip collections and "
        "Windows system trees via dissect.target",
        type=ModuleType.SOURCE,
        requirements=(DISSECT_TARGET,),
        priority=10,
    )

    def can_open(self, path: Path) -> bool:
        path = Path(path)
        if path.is_file():
            name = path.name.casefold()
            return name.endswith(IMAGE_SUFFIXES) or name.endswith(".tar.gz")
        if path.is_dir():
            return _has_dir_ci(path, "windows", "system32") or _has_dir_ci(path, "c", "windows", "system32")
        return False

    def open(self, path: Path) -> TargetEvidence:
        path = Path(path)
        if path.is_dir():
            check_directory_containment(path)
        else:
            check_disk_references(path)
        return TargetEvidence(open_target(path))
