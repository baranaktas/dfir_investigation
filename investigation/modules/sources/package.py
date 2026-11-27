"""An investigation collection package (folder or zip): manifest-verified, files/ read through dissect."""

from __future__ import annotations

import atexit
import gc
import io
import json
import logging
import os
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterator

from investigation.core.module import ModuleMeta, ModuleType, SourceModule
from investigation.core.package import (MANIFEST_NAME, UNVERIFIED_PREFIX, ManifestError, _unsafe,
                                        dedup_problem, verify_manifest)
from investigation.core.registry import register
from investigation.core.source import EvidenceSource
from investigation.modules.sources import target as target_mod
from investigation.modules.collectors.base import read_csv

log = logging.getLogger("investigation")

_INFO_KEYS = ("hostname", "local_timezone")


COPY_BUDGET = 1024**3
HEADROOM = 1024**3


def _manifest_problem(data: bytes) -> str | None:
    """Why `data` is not an Investigation manifest, or None when it is one."""
    try:
        m = json.loads(data.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError) as exc:
        return f"{MANIFEST_NAME} is not a valid Investigation manifest: {exc}"
    if not isinstance(m, dict) or "format_version" not in m:
        return f"{MANIFEST_NAME} is not a valid Investigation manifest: missing format_version"
    return None


def _check_folder_manifest(path: Path) -> bool:
    """True for a folder with a usable manifest.json, False without one; raises ManifestError for a rejected one."""
    manifest = path / MANIFEST_NAME
    if not manifest.is_file():
        return False
    try:
        problem = _manifest_problem(manifest.read_bytes())
    except OSError as exc:
        problem = f"cannot read {MANIFEST_NAME}: {exc}"
    if problem:
        raise ManifestError(problem)
    return True


def _safe_parts(name: str) -> tuple[str, ...]:
    """Path parts of a zip member name, or () when unsafe (absolute, '..', drive letter, __MACOSX)."""
    name = name.replace("\\", "/")
    parts = PurePosixPath(name).parts
    if not parts or name.startswith("/") or ".." in parts or any(":" in p for p in parts) or parts[0] == "__MACOSX":
        return ()
    return parts


def _zip_manifest(z: zipfile.ZipFile) -> tuple[str, bytes] | None:
    """(prefix, manifest bytes): prefix '' if manifest.json is at the zip root, 'dir/' if in the single top folder."""
    members = {}
    for info in z.infolist():
        parts = _safe_parts(info.filename)
        if parts and not info.is_dir():
            members["/".join(parts)] = info
    tops = {n.split("/", 1)[0] for n in members}
    for prefix in ("", next(iter(tops)) + "/" if len(tops) == 1 else None):
        info = members.get(prefix + MANIFEST_NAME) if prefix is not None else None
        if info is not None:
            with z.open(info) as fh:
                return prefix, fh.read()
    return None


def _safe_extract(z: zipfile.ZipFile, dest: Path) -> None:
    chosen = []
    for info in z.infolist():
        parts = _safe_parts(info.filename)
        if info.is_dir() or not parts or stat.S_ISLNK(info.external_attr >> 16):
            continue
        chosen.append((info, parts))
    budget = sum(i.file_size for i, _ in chosen)
    if budget > shutil.disk_usage(dest).free - HEADROOM:
        raise ValueError("zip extracts to more than the free space available")
    for info, parts in chosen:
        target = dest.joinpath(*parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        with z.open(info) as src, open(target, "wb") as out:
            while chunk := src.read(1024 * 1024):
                budget -= len(chunk)
                if budget < 0:
                    raise ValueError("zip extracts to more than its declared size")
                out.write(chunk)


class PackageEvidence(EvidenceSource):
    def __init__(self, root: Path, cleanup: Path | None = None):
        self.package_root = Path(root)
        self._cleanup = cleanup
        try:
            manifest = json.loads((self.package_root / MANIFEST_NAME).read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            manifest = {}
        self.manifest = manifest if isinstance(manifest, dict) else {}
        self.name = str(self.manifest.get("hostname") or self.package_root.name)
        self._errors: list[str] = []
        self.notes: list[str] = []
        self._target = None
        self._subs: list[tuple[str, EvidenceSource]] | None = None
        self._temps: list[Path] = []
        self._budget = [COPY_BUDGET]
        self._not_materialised = 0
        self.memory_image: Path | None = None
        self.target = None
        self.is_system = False
        try:
            target_mod.check_directory_containment(self.package_root)
        except ValueError as exc:
            self._errors.append(str(exc))
            self._subs = []
            return
        try:
            for msg in dict.fromkeys(verify_manifest(self.package_root)):
                if msg.startswith(UNVERIFIED_PREFIX):
                    self.notes.append(msg)
                    log.info("%s", msg)
                else:
                    self._errors.append(msg)
        except Exception as exc:
            self._errors.append(f"cannot verify manifest: {type(exc).__name__}: {exc}")
        image = self._inside("memory/memory.raw")
        if image is not None and image.is_file():
            self.memory_image = image
        files = self._inside("files")
        if files is not None and files.is_dir():
            try:
                self._target = target_mod.TargetEvidence(target_mod.open_target(files))
            except Exception as exc:
                self._errors.append(f"cannot open files/: {type(exc).__name__}: {exc}")
        self.target = self._target.target if self._target else None
        self.is_system = bool(self._target and self._target.is_system)

    def _inside(self, rel: str) -> Path | None:
        """root/rel unless it, or an ancestor below the root, is a symlink or it resolves outside the package."""
        p = self.package_root
        for part in rel.split("/"):
            p = p / part
            if target_mod.is_link(p):
                self._errors.append(f"ignored symlink inside package: {rel}")
                return None
        if p.exists() and not p.resolve().is_relative_to(self.package_root.resolve()):
            self._errors.append(f"ignored path outside package: {rel}")
            return None
        return p

    def iter_files(self) -> Iterator[str]:
        return self._target.iter_files() if self._target else iter(())

    def glob(self, pattern: str) -> Iterator[str]:
        return self._target.glob(pattern) if self._target else iter(())

    def open(self, path: str) -> BinaryIO:
        if not self._target:
            raise FileNotFoundError(path)
        return self._target.open(path)

    def stat(self, path: str):
        return self._target.stat(path) if self._target else (None, None)

    def system_info(self) -> dict[str, str]:
        info = self._target.system_info() if self._target else {}
        csv_path = self._inside("volatile/system_info.csv")
        if csv_path is not None and csv_path.is_file():
            try:
                for row in read_csv(csv_path):
                    key, value = row.get("key", ""), row.get("value", "")
                    if value and (key in _INFO_KEYS or key.startswith("os_")):
                        info.setdefault(key, value)
            except Exception:
                pass
        return info

    def access_errors(self) -> list[str]:
        return self._errors + (self._target.access_errors() if self._target else [])

    def _identical_copies(self) -> dict[str, dict[str, str]]:
        """{shadow name: {path below vss/<name>/: stored file it is identical to}} for sound entries only.
        An entry must read vss/<n>/<L>/<sub> -> files/<L>/<sub> with a plain relative <sub>; anything else is
        reported and ignored."""
        entries = self.manifest.get("files")
        entries = entries if isinstance(entries, list) else []
        by_path = {e["path"]: e for e in entries if isinstance(e, dict) and isinstance(e.get("path"), str)}
        found: dict[str, dict[str, str]] = {}
        for rel, e in by_path.items():
            if "same_as" not in e:
                continue
            parts = rel.split("/")
            if not parts or parts[0] != "vss":
                continue
            same = e.get("same_as")
            ok = (len(parts) >= 4 and parts[1].isascii() and parts[1].isdecimal() and str(int(parts[1])) == parts[1]
                  and len(parts[2]) == 1 and parts[2].isascii() and parts[2].isalpha()
                  and all(p not in ("", ".", "..") and not any(c in p for c in ":\\") for p in parts[3:])
                  and same == "/".join(["files", parts[2], *parts[3:]])
                  and not _unsafe(rel, self.package_root) and not _unsafe(same, self.package_root)
                  and dedup_problem(e, by_path, self.package_root) is None)
            if ok:
                found.setdefault(parts[1], {})["/".join(parts[2:])] = same
            else:
                self._errors.append(f"ignored invalid identical-copy entry: {rel!r} -> {same!r}")
        return found

    def _shadow_tree(self, name: str, same: dict[str, str]) -> Path:
        """A temporary tree with the shadow's own files and, for files stored only once, the copy under files/.
        Identical copies are hard-linked; copying them is limited to COPY_BUDGET bytes in all."""
        tmp = Path(tempfile.mkdtemp(prefix="investigation-vss-"))
        self._temps.append(tmp)
        base = self._inside(f"vss/{name}")
        if base is not None and base.is_dir():
            target_mod.check_directory_containment(base)
            for dirpath, _dirs, names in os.walk(base):
                for n in names:
                    src = Path(dirpath) / n
                    _link_or_copy(src, tmp / src.relative_to(base))
        root = tmp.resolve()
        for sub, original in same.items():
            src = self._inside(original)
            dest = tmp / sub
            if src is None or not src.is_file() or dest.exists():
                continue
            if not dest.resolve().is_relative_to(root):
                self._errors.append(f"ignored identical-copy entry that leaves the shadow tree: vss/{name}/{sub}")
                continue
            if not _link_or_copy(src, dest, self._budget):
                self._not_materialised += 1
        return tmp

    def sub_sources(self) -> list[tuple[str, EvidenceSource]]:
        """One source per vss/<n>/ shadow copy tree; a tree that cannot be read is reported and skipped."""
        if self._subs is not None:
            return self._subs
        self._subs = []
        vss = self._inside("vss")
        if vss is None or not vss.is_dir():
            return self._subs
        try:
            names = {n for n in os.listdir(vss) if n.isascii() and n.isdecimal() and str(int(n)) == n}
        except OSError as exc:
            self._errors.append(f"cannot list vss/: {type(exc).__name__}: {exc}")
            return self._subs
        identical = self._identical_copies()
        for name in sorted(names | set(identical), key=int):
            rel = f"vss/{name}"
            try:
                if name in identical:
                    d = self._shadow_tree(name, identical[name])
                else:
                    d = self._inside(rel)
                    if d is None or not d.is_dir():
                        continue
                    target_mod.check_directory_containment(d)
                self._subs.append((f"vss:{name}", target_mod.TargetEvidence(target_mod.open_target(d))))
            except Exception as exc:
                self._errors.append(f"cannot open {rel}/: {type(exc).__name__}: {exc}")
        if self._not_materialised:
            self.notes.append(f"{self._not_materialised} unchanged shadow-copy files were not materialised "
                              "(copy budget)")
        return self._subs

    def close(self) -> None:
        for _, sub in self._subs or []:
            try:
                sub.close()
            except Exception:
                pass
        self._subs = None
        if self._target:
            self._target.close()
            self._target = None
        for tmp in self._temps:
            _remove_tree(tmp)
        self._temps = []
        if self._cleanup:
            path, self._cleanup = self._cleanup, None
            _remove_tree(path)


def _link_or_copy(src: Path, dest: Path, budget: list[int] | None = None) -> bool:
    """Hard-link src to dest, else copy it. With a budget (a one-item list of bytes left) a copy that would
    exceed it is not made and False is returned."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(src, dest)
        return True
    except OSError:
        pass
    if budget is not None:
        size = src.stat().st_size
        if size > budget[0]:
            return False
        budget[0] -= size
    shutil.copyfile(src, dest)
    return True


def _close_files_under(path) -> None:
    """Close every file object still open below `path`. dissect has no Target.close() and keeps hive file
    objects alive through internal references, and Windows refuses to delete open files. The directory is
    our own extraction, so closing what is left open in it is safe."""
    root = os.path.normcase(os.path.realpath(path)) + os.sep
    gc.collect()
    for obj in gc.get_objects():
        try:
            if isinstance(obj, io.IOBase) and not obj.closed:
                name = getattr(obj, "name", None)
                if isinstance(name, str) and os.path.normcase(os.path.realpath(name)).startswith(root):
                    obj.close()
        except Exception:
            continue


def _remove_tree(path) -> None:
    """Delete the extracted temp dir: close what dissect left open in it, then retry once after a garbage
    collection; whatever still remains is removed at interpreter exit."""
    _close_files_under(path)
    try:
        shutil.rmtree(path)
        return
    except OSError:
        pass
    gc.collect()
    try:
        shutil.rmtree(path)
    except OSError:
        atexit.register(shutil.rmtree, path, ignore_errors=True)


@register
class PackageSource(SourceModule):
    meta = ModuleMeta(
        name="investigation_package",
        description="Investigation collection package (folder or .zip) with manifest verification",
        type=ModuleType.SOURCE,
        priority=5,
    )

    def can_open(self, path: Path) -> bool:
        path = Path(path)
        if path.is_dir():
            return _check_folder_manifest(path)
        if path.is_file() and path.name.casefold().endswith(".zip"):
            try:
                with zipfile.ZipFile(path) as z:
                    found = _zip_manifest(z)
            except ManifestError:
                raise
            except Exception:
                return False
            if found is None:
                return False
            problem = _manifest_problem(found[1])
            if problem:
                raise ManifestError(problem)
            return True
        return False

    def open(self, path: Path) -> PackageEvidence:
        path = Path(path)
        if path.is_dir():
            return PackageEvidence(path)
        tmp = Path(tempfile.mkdtemp(prefix="investigation-pkg-"))
        try:
            with zipfile.ZipFile(path) as z:
                found = _zip_manifest(z)
                prefix = found[0] if found else ""
                _safe_extract(z, tmp)
            return PackageEvidence(tmp / prefix.rstrip("/") if prefix else tmp, cleanup=tmp)
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
