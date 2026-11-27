"""One normalised view of every command found in the evidence, with suspicious-command patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterator

from investigation.core.models import Event, Severity
from investigation.core.store import EventStore

SECURITY_4688 = "Security 4688"
SYSMON_1 = "Sysmon 1"
PS_4104 = "PowerShell 4104"
PS_4103 = "PowerShell 4103"
PS_HISTORY = "PowerShell history"
LIVE_PROCESS = "Live process"
MEMORY_CMDLINE = "Memory cmdline"
MEMORY_CONSOLE = "Memory console"
RUN_MRU = "RunMRU"

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
PS_CHANNEL = "Microsoft-Windows-PowerShell/Operational"
EVTX_PROCESS = (SECURITY_4688, SYSMON_1)
ROW_HEAD = 300


@dataclass(frozen=True)
class CommandPattern:
    id: str
    title: str
    severity: Severity
    mitre: tuple[str, ...]
    description: str
    regexes: tuple[str, ...]
    covered_by_other_rules: frozenset[str] = frozenset()

    def compiled(self) -> list[re.Pattern[str]]:
        return [re.compile(r, re.IGNORECASE) for r in self.regexes]


_PS_SOURCES = frozenset({PS_4104, PS_HISTORY, MEMORY_CMDLINE})
_PROCESS_SOURCES = frozenset(EVTX_PROCESS)

PATTERNS: tuple[CommandPattern, ...] = (
    CommandPattern(
        "INV-CMD-001", "Encoded command or download cradle", Severity.HIGH, ("T1059.001", "T1027", "T1105"),
        "A command uses an encoded PowerShell payload, a download cradle or fetches a URL with "
        "Invoke-WebRequest/iwr/curl/wget.",
        (r"(?<![\w-])-(?:enc|encodedcommand|ec)\s", r"-e\s+(?:jab|sqb)", r"frombase64string", r"downloadstring",
         r"downloadfile", r"(?<![\w-])iex[\s(]", r"invoke-expression", r"net\.webclient",
         r"-nop\w*\s+-w\w*\s+hidden", r"(?<![\w-])(?:invoke-webrequest|iwr|curl|wget|start-bitstransfer)\b[^|;\r\n]*https?://"),
        _PS_SOURCES),
    CommandPattern(
        "INV-CMD-002", "Mimikatz or AMSI bypass", Severity.CRITICAL, ("T1003.001", "T1562.001"),
        "A command mentions Mimikatz or tampers with AMSI.",
        (r"mimikatz", r"sekurlsa::", r"amsiutils", r"amsiinitfailed"), _PS_SOURCES),
    CommandPattern(
        "INV-CMD-003", "Shadow copy deletion or recovery disabled", Severity.CRITICAL, ("T1490",),
        "Shadow copies were deleted or recovery was disabled - the usual step before ransomware encryption.",
        (r"vssadmin(?:\.exe)?\s+delete\s+shadows", r"shadowcopy\s+delete", r"bcdedit.*recoveryenabled\s+no",
         r"wbadmin\s+delete\s+(?:catalog|backup)"), _PROCESS_SOURCES),
    CommandPattern(
        "INV-CMD-004", "Event log cleared with wevtutil", Severity.HIGH, ("T1070.001",),
        "wevtutil was used to clear an event log.", (r"wevtutil(?:\.exe)?\s+(?:cl|clear-log)\b",)),
    CommandPattern(
        "INV-CMD-005", "Local account created or added to Administrators", Severity.HIGH, ("T1136.001", "T1098"),
        "net user /add or net localgroup administrators /add was run.",
        (r"\bnet1?(?:\.exe)?\s+user\s+.*/add\b", r"\bnet1?(?:\.exe)?\s+localgroup\s+administrators\s+.*/add\b")),
    CommandPattern(
        "INV-CMD-006", "Registry hive saved to a file", Severity.HIGH, ("T1003.002",),
        "reg save was used on the SAM, SYSTEM or SECURITY hive - offline credential extraction.",
        (r"\breg(?:\.exe)?\s+save\s+hklm\\(?:sam|system|security)\b",)),
    CommandPattern(
        "INV-CMD-007", "File download with certutil or bitsadmin", Severity.HIGH, ("T1105", "T1218"),
        "certutil or bitsadmin used to download or decode a file.",
        (r"certutil(?:\.exe)?\s+.*-(?:urlcache|decode)", r"bitsadmin(?:\.exe)?\s+.*/transfer"), _PROCESS_SOURCES),
    CommandPattern(
        "INV-CMD-008", "Scheduled task or service created from the command line", Severity.MEDIUM,
        ("T1053.005", "T1543.003"), "schtasks /create or sc create was run.",
        (r"\bschtasks(?:\.exe)?\s+.*/create\b", r"\bsc(?:\.exe)?\s+(?:\\\\\S+\s+)?create\s")),
    CommandPattern(
        "INV-CMD-009", "Microsoft Defender weakened from the command line", Severity.HIGH, ("T1562.001",),
        "Set-MpPreference -Disable* or Add-MpPreference -ExclusionPath changes Defender protection.",
        (r"set-mppreference\s+.*-disable\w+", r"add-mppreference\s+.*-exclusion\w+")),
)
_COMPILED = [(p, p.compiled()) for p in PATTERNS]


def match_patterns(command: str) -> list[CommandPattern]:
    return [p for p, regs in _COMPILED if any(r.search(command) for r in regs)]


@dataclass(frozen=True)
class CommandRow:
    time: datetime | None
    source: str
    user: str
    host: str
    process: str
    command: str
    source_file: str
    event: Event
    rules: tuple[str, ...] = ()

    @property
    def head(self) -> str:
        return self.command[:ROW_HEAD]

    @property
    def rest(self) -> str:
        return self.command[ROW_HEAD:]


def _text(v: Any) -> str:
    return "" if v is None else str(v).strip()


def _proc(name: Any, pid: Any) -> str:
    name, pid = _text(name), _text(pid)
    return f"{name} pid={pid}" if name and pid else name or (f"pid={pid}" if pid else "")


def _extract(e: Event) -> tuple[str, str, str, str | None] | None:
    """(source label, command, process, time kind) or None when the event carries no command."""
    f = e.fields
    a = e.artifact
    if a == "evtx":
        channel, eid = _text(f.get("Channel")), _text(f.get("EventID"))
        if eid == "4688" and channel == "Security":
            return SECURITY_4688, _text(f.get("CommandLine")), _proc(f.get("NewProcessName"), f.get("NewProcessId")), "t"
        if eid == "1" and channel == SYSMON_CHANNEL:
            return SYSMON_1, _text(f.get("CommandLine")), _proc(f.get("Image"), f.get("ProcessId")), "t"
        if channel == PS_CHANNEL and eid == "4104":
            return PS_4104, _text(f.get("ScriptBlockText")), "", "t"
        if channel == PS_CHANNEL and eid == "4103":
            return PS_4103, _text(f.get("Payload")), "", "t"
        return None
    if a == "powershell_history":
        return PS_HISTORY, _text(f.get("command")), "", None
    if a == "live_process":
        return LIVE_PROCESS, _text(f.get("cmdline")), _proc(f.get("name"), f.get("pid")), "live"
    if a == "memory_cmdline":
        return MEMORY_CMDLINE, _text(f.get("Args")), _proc(f.get("Process"), f.get("PID")), None
    if a == "memory_console":
        return MEMORY_CONSOLE, _text(f.get("Data")), _proc(f.get("Process"), f.get("PID")), None
    if a == "mru" and e.message.startswith("Run:"):
        return RUN_MRU, _text(f.get("value")), "", None
    return None


_QUERIES: tuple[tuple[str, dict[str, Any] | None], ...] = (
    ("evtx", {"EventID": 4688}), ("evtx", {"EventID": 1}), ("evtx", {"EventID": 4104}), ("evtx", {"EventID": 4103}),
    ("powershell_history", None), ("live_process", None), ("memory_cmdline", None), ("memory_console", None),
    ("mru", None),
)


def _events(store: EventStore) -> Iterator[Event]:
    for artifact, cond in _QUERIES:
        yield from store.iter_events(artifact=artifact, field_equals=cond)


def collect_commands(store: EventStore) -> list[CommandRow]:
    """Every command in the store, time-ordered; rows without a time come last, grouped by source file."""
    rows: list[CommandRow] = []
    for e in _events(store):
        got = _extract(e)
        if got is None or not got[1]:
            continue
        source, command, process, kind = got
        timed = kind == "t" or (kind == "live" and "no_timestamp" not in e.tags)
        rules = tuple(p.id for p in match_patterns(command))
        rows.append(CommandRow(
            time=e.timestamp if timed and "no_timestamp" not in e.tags else None, source=source,
            user=e.user or _text(e.fields.get("User")), host=e.host or "", process=process, command=command,
            source_file=e.source_file, event=e, rules=rules))
    live_keys = {(r.source, r.time, r.command) for r in rows if "vss" not in r.event.tags}
    seen: set[tuple[str, str, str, str]] = set()
    kept: list[CommandRow] = []
    for r in rows:
        if "vss" in r.event.tags and (r.source, r.time, r.command) in live_keys:
            continue
        if r.source == MEMORY_CONSOLE:
            key = (r.source, r.source_file.split(":")[0], r.process, r.command)
            if key in seen:
                continue
            seen.add(key)
        kept.append(r)
    floor = datetime.min.replace(tzinfo=timezone.utc)
    order = {id(r): i for i, r in enumerate(kept)}
    kept.sort(key=lambda r: (r.time is None, r.time or floor, r.source_file if r.time is None else "", order[id(r)]))
    return kept
