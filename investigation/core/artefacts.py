"""Events the collection itself caused, recognised from the package manifest."""

from __future__ import annotations

import json
import re
import zipfile
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable, Iterator

from investigation.core.models import Event
from investigation.core.package import MANIFEST_NAME

TAG = "collection_artefact"
MARGIN = timedelta(minutes=2)

PROCESS_FIELDS = ("Image", "ParentImage", "NewProcessName", "ParentProcessName", "ProcessName", "SourceImage",
                  "TargetImage", "path", "filename", "prefetch", "Application")
SERVICE_EVENT_IDS = {"7045", "4697", "7036", "7040", "7009", "7000", "7023"}
PMEM_SERVICE = re.compile(r"^pmem$", re.IGNORECASE)
PMEM_TEMP = re.compile(r"\\temp\\pme[^\\]*\.tmp", re.IGNORECASE)
VSS_PROVIDERS = ("vss", "volsnap", "microsoft-windows-volumesnapshot-driver", "volume shadow copy")
SHA256 = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{64})(?![0-9a-fA-F])")
WINPMEM_PREFIX = "winpmem"
PREFETCH_NAME = re.compile(r"^(?P<exe>.+?)-[0-9A-Fa-f]{8}\.pf$")


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


def collector_from_manifest(manifest: dict | None) -> Collector | None:
    if not manifest:
        return None
    start, end = _parse_time(manifest.get("started_utc")), _parse_time(manifest.get("finished_utc"))
    if start is None or end is None:
        return None
    info = manifest.get("collector")
    info = info if isinstance(info, dict) else {}
    return Collector(str(info.get("name") or "").strip(), str(info.get("sha256") or "").strip().lower(), start, end)


def load_collector(input_path: Path) -> Collector | None:
    """The collector of a collection package, or None when the input is not one."""
    return collector_from_manifest(_read_manifest(Path(input_path)))


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


def _flat(event: Event) -> str:
    return event.message + " " + " ".join(str(v) for v in event.fields.values())


def _is_collector_process(event: Event, collector: Collector) -> bool:
    names = _field_exe_names(event)
    wanted = {collector.name.casefold()} if collector.name else set()
    hit = bool(names & wanted) or any(n.startswith(WINPMEM_PREFIX) for n in names)
    if not hit:
        command = str(event.fields.get("CommandLine") or "").casefold()
        eid = str(event.fields.get("EventID") or "")
        if eid in ("4688", "1") and command and (
                (collector.name and collector.name.casefold() in command) or WINPMEM_PREFIX in command):
            return True
        return False
    hashes = _hashes(event)
    if collector.sha256 and hashes and collector.sha256 not in hashes and not any(
            n.startswith(WINPMEM_PREFIX) for n in names):
        return False
    return True


def _is_pmem_service(event: Event) -> bool:
    eid = str(event.fields.get("EventID") or "")
    if event.artifact == "evtx" and eid in SERVICE_EVENT_IDS:
        for key in ("ServiceName", "param1"):
            if PMEM_SERVICE.match(str(event.fields.get(key) or "").strip()):
                return True
    return bool(PMEM_TEMP.search(_flat(event)))


def _is_volume_access(event: Event) -> bool:
    if event.artifact != "evtx":
        return False
    provider = str(event.fields.get("Provider_Name") or event.fields.get("Provider") or "").casefold()
    return any(provider == p or provider.startswith(p) for p in VSS_PROVIDERS)


def is_artefact(event: Event, collector: Collector | None) -> bool:
    """True for an event the collection itself created: inside the collection window (+-2 minutes) and either
    the WinPmem service or its temp driver file, activity of the collector executable (same name, and the same
    hash when the event carries one), or shadow copy and volume service events."""
    if collector is None or "no_timestamp" in event.tags:
        return False
    start, end = collector.window
    if not start <= event.timestamp <= end:
        return False
    return _is_pmem_service(event) or _is_collector_process(event, collector) or _is_volume_access(event)


def mark(events: Iterable[Event], collector: Collector | None) -> Iterator[Event]:
    for event in events:
        if is_artefact(event, collector):
            yield replace(event, tags=tuple(event.tags) + (TAG,))
        else:
            yield event
