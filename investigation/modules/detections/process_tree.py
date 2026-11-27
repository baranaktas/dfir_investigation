"""Process tree checks (normal Windows process tree, suspicious parents, memory-only checks).

Works on memory_process (Volatility pslist/psscan) and live_process (live collector) events.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterator

from investigation.core.models import Event, Finding, Severity
from investigation.core.module import DetectionModule, ErrorSink, ModuleMeta, ModuleType
from investigation.core.registry import register
from investigation.core.requirements import Context
from investigation.core.store import EventStore

EXPECTED_PARENT = {
    "smss.exe": {"system", "smss.exe"},
    "wininit.exe": {"smss.exe", ""},
    "csrss.exe": {"smss.exe", ""},
    "winlogon.exe": {"smss.exe", ""},
    "services.exe": {"wininit.exe"},
    "lsass.exe": {"wininit.exe"},
    "lsaiso.exe": {"wininit.exe"},
    "svchost.exe": {"services.exe", "msmpeng.exe"},
}
SINGLETONS = {"wininit.exe", "services.exe", "lsass.exe", "lsaiso.exe"}


def _name(e: Event) -> str:
    return str(e.fields.get("ImageFileName") or "").strip().casefold()


def _created(e: Event):
    """Process create time: the event timestamp for live_process, CreateTime for memory_process."""
    if e.artifact == "live_process":
        return e.timestamp if e.timestamp_desc == "Process Started" else None
    raw = e.fields.get("CreateTime")
    if not raw or raw == "N/A":
        return None
    try:
        dt = raw if isinstance(raw, datetime) else datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _created_after(parent: Event, child: Event) -> bool:
    p, c = _created(parent), _created(child)
    return p is not None and c is not None and p > c


def _running(e: Event) -> bool:
    return e.fields.get("ExitTime") in (None, "", "N/A")


@register
class ProcessTree(DetectionModule):
    meta = ModuleMeta(
        name="process_tree",
        description="Process tree anomalies: wrong parents, duplicate singletons, LSASS children, hidden processes",
        type=ModuleType.DETECTION,
    )

    def detect(self, store: EventStore, ctx: Context, errors: ErrorSink | None = None) -> Iterator[Finding]:
        for artifact in ("memory_process", "live_process"):
            yield from self._check(list(store.iter_events(artifact=artifact)))

    @staticmethod
    def _check(procs: list[Event]) -> Iterator[Finding]:
        if not procs:
            return
        active = [e for e in procs if "hidden_or_exited" not in e.tags]
        by_pid = {e.fields.get("PID"): e for e in active}

        wrong_parent, lsass_children, hidden = [], [], [e for e in procs if "hidden_or_exited" in e.tags]
        counts: dict[str, list[Event]] = defaultdict(list)
        lsass_pids = {e.fields.get("PID") for e in active if _name(e) == "lsass.exe"}
        for e in active:
            name = _name(e)
            parent = by_pid.get(e.fields.get("PPID"))
            if (parent is not None and _name(parent) not in EXPECTED_PARENT.get(name, ())
                    and _created_after(parent, e)):
                parent = None
            parent_name = _name(parent) if parent else ""
            if name in EXPECTED_PARENT and parent_name not in EXPECTED_PARENT[name]:
                wrong_parent.append(e)
            if name in SINGLETONS and _running(e):
                counts[name].append(e)
            if e.fields.get("PPID") in lsass_pids:
                lsass_children.append(e)

        if wrong_parent:
            yield Finding("INV-PROC-001", "Unexpected parent for a system process", Severity.HIGH,
                          "A Windows system process was started by an unexpected parent - typical of masquerading "
                          "malware (e.g. svchost.exe not started by services.exe).", ("T1036.005",), wrong_parent)
        dupes = [e for evs in counts.values() if len(evs) > 1 for e in evs]
        if dupes:
            yield Finding("INV-PROC-002", "Multiple instances of a singleton system process", Severity.CRITICAL,
                          "wininit/services/lsass run exactly once; a second running copy is almost always malware "
                          "using a system name.", ("T1036.005",), dupes)
        if lsass_children:
            yield Finding("INV-PROC-003", "LSASS has child processes", Severity.CRITICAL,
                          "lsass.exe never starts processes; a child suggests code running inside LSASS "
                          "(credential theft or injection).", ("T1003.001", "T1055"), lsass_children)
        if hidden:
            yield Finding("INV-PROC-004", "Process found only by pool scanning (hidden or exited)", Severity.MEDIUM,
                          "psscan found a process that is not in the active process list: either it exited or it "
                          "was unlinked by a rootkit (DKOM).", ("T1014",), hidden,
                          note="Exited processes also appear here - check ExitTime before calling it a rootkit.")
