"""Events the collection itself caused, recognised from the package manifest."""

from __future__ import annotations

import json
import re
import zipfile
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable, Iterable, Iterator

from investigation.core.models import Event, Finding
from investigation.core.package import MANIFEST_NAME

TAG = "collection_artefact"
MARGIN = timedelta(minutes=2)
MAX_WINDOW = timedelta(hours=24)

PROCESS_FIELDS = ("Image", "NewProcessName", "ProcessName", "SourceImage", "path", "filename", "prefetch",
                  "Application")
PMEM_SERVICE_EVENT_IDS = {"7045", "4697"}
PMEM_IMAGE_PATH = re.compile(
    r"^(?:\\\?\?\\)?(?:[A-Za-z]:|%[A-Za-z]+%)?(?:\\[^\\]+)*\\Temp\\pme[0-9A-Fa-f]+\.tmp$", re.IGNORECASE)
SHA256 = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{64})(?![0-9a-fA-F])")
PREFETCH_NAME = re.compile(r"^(?P<exe>.+?)-[0-9A-Fa-f]{8}\.pf$")
POSSIBLE_TAG = "possible_collection_artefact"
POSSIBLE_NOTE = "possibly created by the collector (name matches, no hash to confirm)"
PMEM_NAME = "pmem"


@dataclass(frozen=True)
class Collector:
    """The tool run that produced a package: executable name and hash, and when it ran."""

    name: str
    sha256: str
    start: datetime
    end: datetime

    @property
    def window(self) -> tuple[datetime, datetime]:
        return self.start - MARGIN, self.end + MARGIN


def _parse_time(value: Any) -> datetime | None:
    try:
        t = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _read_manifest(path: Path) -> dict | None:
    try:
        if path.is_dir():
            raw = (path / MANIFEST_NAME).read_text(encoding="utf-8-sig")
        elif zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as z:
                names = [n for n in z.namelist() if PurePosixPath(n).name == MANIFEST_NAME and n.count("/") <= 1]
                if not names:
                    return None
                raw = z.read(min(names, key=len)).decode("utf-8-sig")
        else:
            return None
        data = json.loads(raw)
    except (OSError, ValueError, zipfile.BadZipFile, KeyError):
        return None
    return data if isinstance(data, dict) else None


def collector_from_manifest(manifest: dict | None, note: Callable[[str], None] | None = None) -> Collector | None:
    """The collector described by a manifest, or None when the manifest has no usable window: a window that ends
    before it starts or lasts longer than MAX_WINDOW is not trusted, so nothing is treated as an artefact."""
    if not manifest:
        return None
    start, end = _parse_time(manifest.get("started_utc")), _parse_time(manifest.get("finished_utc"))
    if start is None or end is None:
        return None
    if end < start or end - start > MAX_WINDOW:
        if note:
            note("collection window in manifest.json is not plausible; no event is treated as a collection artefact")
        return None
    info = manifest.get("collector")
    info = info if isinstance(info, dict) else {}
    return Collector(str(info.get("name") or "").strip(), str(info.get("sha256") or "").strip().lower(), start, end)


def load_collector(input_path: Path, note: Callable[[str], None] | None = None) -> Collector | None:
    """The collector of a collection package, or None when the input is not one."""
    return collector_from_manifest(_read_manifest(Path(input_path)), note)


def _base(value: Any) -> str:
    text = str(value or "").strip().strip('"')
    if not text:
        return ""
    return PureWindowsPath(text).name.casefold()


def _field_exe_names(event: Event) -> set[str]:
    names: set[str] = set()
    for key in PROCESS_FIELDS:
        value = event.fields.get(key)
        if value in (None, ""):
            continue
        base = _base(value)
        m = PREFETCH_NAME.match(base) if base.endswith(".pf") else None
        names.add(m.group("exe").casefold() if m else base)
    return names


def _hashes(event: Event) -> set[str]:
    found: set[str] = set()
    for key, value in event.fields.items():
        if "sha256" in str(key).casefold() or str(key) == "Hashes":
            found.update(h.lower() for h in SHA256.findall(str(value)))
    return found


def _winpmem_name_and_hash() -> tuple[str, str]:
    from investigation.modules.collectors.memory import WINPMEM_NAME, WINPMEM_SHA256

    return WINPMEM_NAME.casefold(), WINPMEM_SHA256.lower()


def _is_pmem_service(event: Event) -> bool:
    if event.artifact != "evtx" or str(event.fields.get("EventID") or "") not in PMEM_SERVICE_EVENT_IDS:
        return False
    return str(event.fields.get("ServiceName") or "") == PMEM_NAME


def _pmem_service_exact(event: Event) -> bool:
    return _is_pmem_service(event) and PMEM_IMAGE_PATH.fullmatch(str(event.fields.get("ImagePath") or "")) is not None


def classify(event: Event, collector: Collector | None) -> str | None:
    """"artefact" for an event the collection itself created, "possible" for one that only matches by name,
    None for a normal event. An artefact lies inside the collection window (+-2 minutes) and is either the
    WinPmem service install with an ImagePath of the form Temp\\pme<hex>.tmp, or an event of the collector
    executable (same name) whose sha256 equals the manifest's collector hash or the pinned WinPmem hash.
    A name match without a hash is never suppressed. Volume shadow copy events are never suppressed."""
    if collector is None or "no_timestamp" in event.tags:
        return None
    start, end = collector.window
    if not start <= event.timestamp <= end:
        return None
    if _is_pmem_service(event):
        return "artefact" if _pmem_service_exact(event) else "possible"
    wp_name, wp_hash = _winpmem_name_and_hash()
    pinned = {h for h in (collector.sha256, wp_hash) if h}
    names = {wp_name} | ({collector.name.casefold()} if collector.name and collector.sha256 else set())
    seen = _field_exe_names(event)
    if not seen & names:
        return None
    hashes = _hashes(event)
    if not hashes:
        return "possible"
    return "artefact" if hashes & pinned else None


def is_artefact(event: Event, collector: Collector | None) -> bool:
    return classify(event, collector) == "artefact"


def mark(events: Iterable[Event], collector: Collector | None) -> Iterator[Event]:
    for event in events:
        kind = classify(event, collector)
        if kind == "artefact":
            yield replace(event, tags=tuple(event.tags) + (TAG,))
        elif kind == "possible":
            yield replace(event, tags=tuple(event.tags) + (POSSIBLE_TAG,))
        else:
            yield event


def is_verified(event: Event) -> bool:
    return TAG in event.tags


def split_findings(findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    """(findings to report, findings made only of verified collection artefacts)."""
    kept: list[Finding] = []
    moved: list[Finding] = []
    for f in findings:
        (moved if f.events and all(is_verified(e) for e in f.events) else kept).append(f)
    return kept, moved
