"""Automatic "file story" and interpretation notes.

For every suspicious executable named in a finding, gather all events that mention it and answer the
standard triage questions: where did it come from, when did it run, who ran it, did it persist,
what did it touch, and what are its hashes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Iterable

from investigation.core.models import Event, EvidenceType, Finding
from investigation.core.store import EventStore

SECTIONS = [
    "Where did it come from?",
    "When did it run?",
    "Who ran it?",
    "Did it persist?",
    "What did it touch?",
    "Hashes",
]
STORY_EVENT_LIMIT = 200
SEARCH_LIMIT = 20_000
MAX_STORIES = 25
ORIGIN_ARTIFACTS = {"browser", "mft", "usnjrnl", "recyclebin"}
SYSTEM_BINARIES = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "svchost.exe", "wmiprvse.exe", "explorer.exe",
    "services.exe", "lsass.exe", "conhost.exe", "mshta.exe", "cscript.exe", "wscript.exe", "regsvr32.exe",
    "certutil.exe", "schtasks.exe", "sc.exe", "net.exe", "net1.exe", "whoami.exe", "taskhostw.exe",
    "winlogon.exe", "wininit.exe", "csrss.exe", "smss.exe", "dllhost.exe", "msiexec.exe", "bitsadmin.exe",
    "wmic.exe", "vssadmin.exe", "reg.exe", "nltest.exe",
}
_NAME = re.compile(r"[\w\-.]{1,64}\.(?:exe|dll|ps1|bat|cmd|vbs|js|hta|scr)\b", re.IGNORECASE)

STATIC_NOTES = {
    "evtx": "Missing events are often an audit-policy gap (4688 and script-block logging are off by default) "
            "or log rollover, not necessarily deletion - check for 1102/104.",
}


@lru_cache(maxsize=1)
def _catalog_notes() -> dict[str, str]:
    try:
        from investigation.modules.parsers.dissect_adapter import load_catalog
    except Exception:
        return {}
    notes: dict[str, str] = {}
    for spec in load_catalog():
        if spec.note and spec.artifact not in notes:
            notes[spec.artifact] = spec.note
    return notes


def notes_for(artifacts: Iterable[str]) -> dict[str, str]:
    """Interpretation caveats for the artifacts that actually produced events."""
    all_notes = {**STATIC_NOTES, **_catalog_notes()}
    return {a: all_notes[a] for a in sorted(set(artifacts)) if a in all_notes}


@dataclass
class FileStory:
    name: str
    sections: dict[str, list[Event]] = field(default_factory=lambda: {s: [] for s in SECTIONS})
    hashes: dict[str, str] = field(default_factory=dict)
    truncated: dict[str, bool] = field(default_factory=lambda: {s: False for s in SECTIONS})
    all_events: list[Event] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "hashes": dict(self.hashes),
            "truncated": {k: v for k, v in self.truncated.items() if v},
            "sections": {s: [e.to_dict() for e in self.sections.get(s, [])] for s in SECTIONS},
        }


def _strings(event: Event) -> Iterable[str]:
    yield event.message
    for v in event.fields.values():
        if isinstance(v, str):
            yield v


def candidate_names(findings: list[Finding]) -> list[str]:
    ordered = sorted(findings, key=lambda f: -int(f.severity))
    names: list[str] = []
    for f in ordered:
        for e in f.events:
            for text in _strings(e):
                for m in _NAME.finditer(text):
                    name = re.split(r"[\\/]", m.group(0))[-1].strip().casefold()
                    stem = name.rsplit(".", 1)[0]
                    if len(stem) < 3 or name in SYSTEM_BINARIES or name in names:
                        continue
                    names.append(name)
                    if len(names) >= MAX_STORIES:
                        return names
    return names


def _hash_key(field_name: str) -> str | None:
    lower = field_name.casefold()
    for algo in ("sha256", "sha1", "md5"):
        if lower.endswith(algo):
            return algo
    return None


def _name_pattern(name: str) -> re.Pattern[str]:
    return re.compile(r"(?:^|[\\/\s\"'=:>])" + re.escape(name) + r"(?=$|[\s\"',;:)<\]])", re.IGNORECASE)


def _mentions(e: Event, rx: re.Pattern[str]) -> bool:
    return any(rx.search(t) for t in _strings(e))


def _is_about(e: Event, name: str) -> bool:
    """True when the event's own path/filename is this file (not just a mention), for hash attribution."""
    for k in ("path", "filename", "name", "app", "deleted_path", "imagepath", "Image", "NewProcessName"):
        v = e.fields.get(k)
        if isinstance(v, str) and re.split(r"[\\/]", v.strip().strip('"'))[-1].casefold() == name.casefold():
            return True
    return False


def build_story(store: EventStore, name: str) -> FileStory:
    story = FileStory(name=name)
    rx = _name_pattern(name)

    def add(section: str, e: Event) -> None:
        if len(story.sections[section]) < STORY_EVENT_LIMIT:
            story.sections[section].append(e)
        else:
            story.truncated[section] = True

    for e in store.search(name, limit=SEARCH_LIMIT):
        if not _mentions(e, rx):
            continue
        story.all_events.append(e)
        et = EvidenceType(e.evidence_type)
        desc = e.timestamp_desc.casefold()
        if e.artifact in ORIGIN_ARTIFACTS or (et is EvidenceType.EXISTENCE and "creat" in desc):
            add("Where did it come from?", e)
        if et is EvidenceType.EXECUTION:
            add("When did it run?", e)
            if e.user:
                add("Who ran it?", e)
        if et is EvidenceType.PERSISTENCE:
            add("Did it persist?", e)
        if et is EvidenceType.FILE_ACCESS or (e.artifact == "prefetch" and e.fields.get("linkedfiles")):
            add("What did it touch?", e)
        if _is_about(e, name):
            for k, v in e.fields.items():
                algo = _hash_key(k)
                if algo and isinstance(v, str) and v and algo not in story.hashes:
                    story.hashes[algo] = v
    return story


def build_stories(store: EventStore, findings: list[Finding]) -> list[FileStory]:
    stories = [build_story(store, n) for n in candidate_names(findings)]
    return [s for s in stories if any(s.sections.values()) or s.hashes]
