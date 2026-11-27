"""Interactive selection menus for the collect command."""

from __future__ import annotations

import platform
import re
import shutil
from pathlib import Path
from dataclasses import dataclass, field
from typing import Callable, Sequence

from investigation.modules.collectors.volumes import Volume, disks_of, physical_disks

CATEGORY_LABELS = {
    "live": "Live data: processes, network, DNS, ARP, services, tasks...",
    "files": "Files: registry, event logs, $MFT, Prefetch, browser history...",
    "memory": "Memory image (WinPmem)",
    "disk": "Disk image (raw copy of whole disks)",
    "vss": "Volume shadow copies",
}
DEFAULT_ON = {"live", "files", "memory"}
CATEGORY_ESTIMATES = {"live": "~1 min", "files": "~5-15 min"}


def _gb(n: int) -> str:
    return f"~{round(n / 10**9)} GB"


def runtime_estimates(drives: Sequence[str] = ()) -> dict[str, str]:
    """Size-based estimates for the disk and memory rows; categories that cannot be sized are omitted."""
    est: dict[str, str] = {}
    try:
        wanted: set[int] = set()
        for d in drives or ["C"]:
            wanted |= disks_of(f"{str(d).rstrip(':').upper()}:\\") or set()
        total = sum(size for n, size in physical_disks() if n in wanted)
        if total:
            est["disk"] = _gb(total)
    except Exception:
        pass
    try:
        import psutil

        est["memory"] = _gb(psutil.virtual_memory().total)
    except Exception:
        pass
    return est


def ask_yes_no(question: str, input_fn: Callable[[str], str] = input,
               print_fn: Callable[[str], None] = print, default: bool = False) -> bool:
    """Ask `question`; Enter gives `default`. The [Y/n] / [y/N] hint is appended here."""
    answer = input_fn(f"{question} [{'Y/n' if default else 'y/N'}] ").strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes", "e", "evet")


def is_arm64() -> bool:
    """Same test as the memory collector's X64 requirement, inverted."""
    return platform.machine().upper() not in ("AMD64", "X86_64")


@dataclass
class CollectionChoice:
    categories: list[str] = field(default_factory=list)
    drives: list[str] = field(default_factory=list)
    output: str = ""
    image_drives: list[str] = field(default_factory=list)


def _vols(volumes) -> list[Volume]:
    """`volumes` may be a list or a callable; a callable is re-read on every call (drives get attached)."""
    return list(volumes() if callable(volumes) else volumes)


def _letter(v: Volume) -> str:
    return v.letter.rstrip(":").upper()


def _system_letter(volumes: Sequence[Volume]) -> str:
    return next((_letter(v) for v in volumes if v.is_system), "C")


def _output_letter(output: str) -> str:
    drive = (output or "")[:2]
    return drive[0].upper() if len(drive) == 2 and drive[1] == ":" and drive[0].isalpha() else ""


SKIP_WORDS = {"skip", "none", "-", "n", "no"}


def _print_drives(vols: Sequence[Volume], out_letter: str, print_fn) -> None:
    print_fn("Drives on this machine:")
    for v in vols:
        letter = _letter(v)
        tags = [t for t, on in (("system", v.is_system), ("output", letter == out_letter)) if on]
        label = f'  "{v.label}"' if v.label else ""
        tag = f"  ({', '.join(tags)})" if tags else ""
        if v.size <= 0:
            print_fn(f"  {letter}:  (no media){label}{tag}")
        else:
            print_fn(f"  {letter}:  {round(v.size / 10**9):>4} GB  {v.fstype}{label}{tag}")


def _pick_drives(volumes, prompt: str, output: str, input_fn, print_fn, default: list[str] | None = None,
                 empty_skips: bool = False, show: bool = True) -> list[str] | None:
    """Ask for drives (letters or labels). Empty -> default (re-ask when there is none); "none" -> None.
    Volumes are re-read on every ask so a drive attached meanwhile is accepted."""
    out_letter = _output_letter(output)
    while True:
        vols = _vols(volumes)
        if show:
            _print_drives(vols, out_letter, print_fn)
        show = False
        text = input_fn(prompt)
        if text.strip().casefold() in SKIP_WORDS or (empty_skips and not text.strip()):
            return None
        by_letter = {_letter(v): _letter(v) for v in vols if v.size > 0}
        no_media = {_letter(v) for v in vols if v.size <= 0}
        by_label = {v.label.casefold(): _letter(v) for v in vols if v.label and v.size > 0}
        letters, bad = [], []
        for tok in text.replace(" ", ",").split(","):
            tok = tok.strip()
            if not tok:
                continue
            key = tok.rstrip(":").upper()
            if key in by_letter:
                letters.append(key)
            elif tok.casefold() in by_label:
                letters.append(by_label[tok.casefold()])
            elif not vols and len(key) == 1 and key.isalpha():
                letters.append(key)
            else:
                bad.append(f"{tok} (no media)" if key in no_media else tok)
        if bad:
            print_fn(f"Unknown drive(s): {', '.join(bad)}. Available: {', '.join(by_letter) or 'none'}")
            show = True
            continue
        if letters:
            return list(dict.fromkeys(letters))
        return list(default) if default is not None else None


def _output_disk_conflict(volumes: Sequence[Volume], drives: Sequence[str], output: str) -> list[str]:
    """Selected drives whose physical disk also holds the output folder."""
    out = _output_letter(output)
    if not out:
        return []
    try:
        out_disks = disks_of(f"{out}:\\") or set()
    except Exception:
        out_disks = set()
    hits = []
    for d in drives:
        if d == out:
            hits.append(d)
            continue
        try:
            if out_disks & (disks_of(f"{d}:\\") or set()):
                hits.append(d)
        except Exception:
            pass
    return hits


def _free_bytes(path: str) -> int | None:
    p = Path(path)
    while not p.exists() and p != p.parent:
        p = p.parent
    try:
        return shutil.disk_usage(p).free
    except OSError:
        return None


def _mkdir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def _gb_of(text: str | None) -> float:
    m = re.search(r"[\d.]+", text or "")
    return float(m.group()) if m else 0.0


def _ask_output(current: str, cats, drives, vols, est, resolve, input_fn, print_fn,
                vss_drives: Sequence[str] = ()) -> str:
    need = (_gb_of(est.get("memory")) if "memory" in cats else 0) + (_gb_of(est.get("disk")) if "disk" in cats else 0)
    while True:
        free = _free_bytes(current)
        drv = Path(current).drive or _output_letter(current) + ":"
        where = f"  (free: {round(free / 10**9)} GB on {drv})" if free is not None else ""
        print_fn(f"Output folder [{current}]{where}")
        print_fn("  Tip: use an external/USB drive, e.g. E:\\")
        text = input_fn("> ").strip()
        if not text:
            path = current
        elif re.fullmatch(r"[A-Za-z]:?", text):
            path = f"{text[0].upper()}:\\"
        else:
            path = str(resolve(text))
        free = _free_bytes(path)
        problems = []
        if "disk" in cats and _output_disk_conflict(vols, drives, path):
            problems.append(f"{_output_letter(path)}: is a drive that will be imaged")
        if need and free is not None and free / 10**9 < need:
            problems.append(f"only {round(free / 10**9)} GB free, about {round(need)} GB needed")
        shadow_hit = "vss" in cats and _output_letter(path) in vss_drives
        if shadow_hit:
            print_fn(f"Warning: writing to {_output_letter(path)}: can make Windows delete its oldest shadow "
                     "copies. Use an external drive for the output.")
        if problems:
            print_fn("Warning: " + "; ".join(problems) + ".")
        if problems or shadow_hit:
            if not ask_yes_no("Use it anyway?", input_fn, print_fn, False):
                continue
        if not Path(path).exists():
            if not ask_yes_no(f"{path} does not exist. Create it?", input_fn, print_fn, True):
                continue
            try:
                _mkdir(path)
            except OSError as exc:
                print_fn(f"Cannot create it: {exc}")
                continue
        return path


def ask_collection(volumes, input_fn: Callable[[str], str] = input,
                   print_fn: Callable[[str], None] = print, arm64: bool = False,
                   estimates: dict[str, str] | None = None, output: str = "",
                   ask_drives: bool = True, fixed_drives: Sequence[str] = (),
                   resolve_output: Callable[[str], object] | None = None,
                   estimate_fn: Callable[[Sequence[str]], dict[str, str]] | None = None,
                   fixed_image_drives: Sequence[str] = ()) -> CollectionChoice | None:
    """Yes/no collection dialogue. Returns None when the examiner declines at "Start?"."""
    est = estimates or {}

    def yn(q, default):
        return ask_yes_no(q, input_fn, print_fn, default)

    cats: list[str] = []
    if yn("Live data (processes, network, services...)?", True):
        cats.append("live")
    if yn("Files (registry, event logs, $MFT, Prefetch...)?", True):
        cats.append("files")
    if arm64:
        print_fn("Memory image: not available on ARM64")
    else:
        mem = f"~{est['memory'].lstrip('~')}, " if "memory" in est else ""
        if yn(f"Memory image ({mem}loads the WinPmem driver temporarily)?", True):
            cats.append("memory")
    if yn("Shadow copies?", False):
        cats.append("vss")
    if yn("Disk image (raw copy of whole disks, not onto the output disk)?", False):
        cats.append("disk")
    if not cats:
        print_fn("Nothing to collect.")
        return None
    system = _system_letter(_vols(volumes))
    drives = list(fixed_drives) if fixed_drives else [system]
    image_drives: list[str] = list(fixed_image_drives)
    shown = False
    skipped: set[str] = set()
    if ask_drives and "files" in cats and not fixed_drives:
        drives = _pick_drives(volumes, f"Collect files from which drives? "
                              f"(Enter = {system}:, e.g. {system},T, or 'skip') ", output, input_fn, print_fn,
                              default=[system])
        shown = True
        if drives is None:
            cats.remove("files")
            drives = [system]
            skipped.add("files")
    if "disk" in cats and not image_drives:
        got = _pick_drives(volumes, "Image which drives? (e.g. T, Enter = skip) ", output, input_fn, print_fn,
                           empty_skips=True, show=not shown)
        if got is None:
            cats.remove("disk")
            skipped.add("disk")
        else:
            image_drives = got
    if not cats:
        print_fn("Nothing to collect.")
        return None
    if "disk" in cats:
        if estimate_fn is not None:
            est = {k: v for k, v in est.items() if k != "disk"}
            est.update({k: v for k, v in estimate_fn(image_drives).items() if k == "disk"})
        if "disk" in est:
            print_fn(f"Disk image size: ~{est['disk'].lstrip('~')}")
    if resolve_output is not None:
        output = _ask_output(output, cats, image_drives, _vols(volumes), est, resolve_output, input_fn, print_fn,
                              vss_drives=drives)
    note = ""
    if "disk" in cats:
        hits = _output_disk_conflict(_vols(volumes), image_drives, output)
        if hits:
            h = ", ".join(f"{d}:" for d in hits)
            note = (f"Note: the output folder is on {_output_letter(output)}:, so {h} itself cannot be "
                    "imaged - use an external drive for the output.")
            print_fn(note)
    print_fn("")
    print_fn(f"Will collect: {', '.join(cats)}")
    if "files" in skipped:
        print_fn("Files from: skipped")
    if "files" in cats:
        print_fn("Files from: " + ", ".join(f"{d}:" for d in drives))
    if "disk" in skipped:
        print_fn("Disk image of: skipped")
    if "disk" in cats:
        print_fn("Disk image of: " + ", ".join(f"{d}:" for d in image_drives))
    if output:
        print_fn(f"Output: {output}")
    if note:
        print_fn(note)
    if not yn("Start?", True):
        return None
    return CollectionChoice(cats, drives, output, image_drives if "disk" in cats else [])


