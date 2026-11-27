"""Windows Event Log (.evtx) parser."""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from typing import Any, Iterator

from investigation.core.models import Event, EvidenceType
from investigation.core.module import ErrorSink, ModuleMeta, ModuleType, ParserModule
from investigation.core.registry import register
from investigation.core.requirements import Context, PythonPackage
from investigation.core.source import EvidenceSource

SYSMON = "Microsoft-Windows-Sysmon/Operational"
_A, _E, _P, _N, _X = (
    EvidenceType.AUTHENTICATION,
    EvidenceType.EXECUTION,
    EvidenceType.PERSISTENCE,
    EvidenceType.NETWORK,
    EvidenceType.EXISTENCE,
)

EVIDENCE_TYPES: dict[tuple[str, int], EvidenceType] = {
    **{("Security", i): _A for i in (4624, 4625, 4634, 4647, 4648, 4672, 4740, 4768, 4769, 4771, 4776)},
    ("Security", 4688): _E,
    **{(SYSMON, 1): _E},
    **{("Microsoft-Windows-PowerShell/Operational", i): _E for i in (4103, 4104)},
    **{("Windows PowerShell", i): _E for i in (400, 403, 800)},
    ("System", 7045): _P,
    ("Security", 4697): _P,
    ("Security", 4698): _P,
    ("Microsoft-Windows-TaskScheduler/Operational", 106): _P,
    ("Microsoft-Windows-WMI-Activity/Operational", 5861): _P,
    **{(SYSMON, i): _P for i in (12, 13, 14, 19, 20, 21)},
    **{(SYSMON, i): _N for i in (3, 22)},
    ("Security", 5140): _N,
    ("Security", 5145): _N,
    **{("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", i): _N for i in (21, 24, 25)},
    **{(SYSMON, i): _X for i in (11, 23, 26)},
}

EVTX_HEADER_SIZE = 4096
EVTX_CHUNK_SIZE = 65536


def truncation_problem(header: bytes, size: int) -> str | None:
    """EVTX files are a 4 KiB header followed by whole 64 KiB chunks; anything else was cut short."""
    if len(header) < 44 or size < EVTX_HEADER_SIZE:
        return f"file is {size} bytes, smaller than the EVTX header"
    chunk_count = struct.unpack_from("<H", header, 42)[0]
    expected = EVTX_HEADER_SIZE + chunk_count * EVTX_CHUNK_SIZE
    if size < expected:
        return f"header announces {chunk_count} chunk(s) = {expected} bytes but file is {size} bytes"
    if (size - EVTX_HEADER_SIZE) % EVTX_CHUNK_SIZE:
        return f"file size {size} is not a whole number of 64 KiB chunks"
    return None


_SYSTEM_PREFIXES = {"Provider", "EventID", "TimeCreated", "Correlation", "Execution", "Security"}
_MESSAGE_KEYS = (
    "ServiceName", "ImagePath", "TargetUserName", "SubjectUserName", "LogonType", "IpAddress",
    "ThreatName", "Path", "Image", "CommandLine", "ParentImage", "TargetImage", "TaskName", "ScriptBlockText",
)


def _blank(v: Any) -> bool:
    return v is None or (isinstance(v, str) and v.strip() in ("", "-"))


def _unwrap(v: Any) -> Any:
    """dissect returns substitution values wrapped in BxmlSub; reduce to plain Python types."""
    for _ in range(5):
        if type(v).__name__ == "BxmlSub":
            v = v.value
        else:
            break
    if isinstance(v, bool) or v is None or isinstance(v, (str, datetime)):
        return v
    if isinstance(v, int):
        return int(v)
    if isinstance(v, float):
        return float(v)
    if isinstance(v, (bytes, bytearray)):
        return bytes(v)
    if isinstance(v, (list, tuple)):
        return ", ".join(str(_unwrap(x)) for x in v)
    return str(v)


def normalize_fields(record: dict[str, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for k, v in record.items():
        if k == "Provider_Guid" or k.startswith("Correlation_") or "xmlns" in k:
            continue
        fields[k] = _unwrap(v)
    for k, v in list(fields.items()):
        if " " in k:
            fields.setdefault(k.replace(" ", ""), v)
    if "ServiceFileName" in fields:
        fields.setdefault("ImagePath", fields["ServiceFileName"])
    for k, v in list(fields.items()):
        prefix, sep, rest = k.partition("_")
        if sep and rest and prefix not in _SYSTEM_PREFIXES and rest not in fields:
            fields[rest] = v
    return fields


def _message(fields: dict[str, Any]) -> str:
    parts = []
    for k in _MESSAGE_KEYS:
        v = fields.get(k)
        if not _blank(v):
            s = str(v).replace("\r", " ").replace("\n", " ")
            parts.append(f"{k}={s[:200]}")
        if len(parts) == 4:
            break
    return f"{fields.get('Channel')} {fields.get('EventID')}: " + " ".join(parts)


def _user(fields: dict[str, Any]) -> str | None:
    for k in ("TargetUserName", "SubjectUserName", "Security_UserID"):
        v = fields.get(k)
        if not _blank(v):
            return str(v)
    return None


def record_to_event(record: dict[str, Any], source_file: str) -> Event | None:
    fields = normalize_fields(record)
    ts = fields.get("TimeCreated_SystemTime")
    if not isinstance(ts, datetime):
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    channel = str(fields.get("Channel") or "")
    try:
        eid = int(fields.get("EventID"))
    except (TypeError, ValueError):
        eid = -1
    host = fields.get("Computer")
    return Event(
        timestamp=ts,
        timestamp_desc="Event Logged",
        artifact="evtx",
        source_file=source_file,
        message=_message(fields),
        host=str(host) if host else None,
        user=_user(fields),
        fields=fields,
        evidence_type=EVIDENCE_TYPES.get((channel, eid), EvidenceType.OTHER),
    )


@register
class EvtxParser(ParserModule):
    meta = ModuleMeta(
        name="evtx",
        description="Windows event logs (*.evtx): Security, System, Sysmon, PowerShell, RDP, Defender, ...",
        type=ModuleType.PARSER,
        requirements=(PythonPackage("dissect.eventlog", "dissect.eventlog", min_version="3.11"),),
        artifacts=("evtx",),
    )

    @staticmethod
    def patterns(source: EvidenceSource) -> list[str]:
        return ["windows/system32/winevt/logs/*.evtx"] if source.is_system else ["**/*.evtx"]

    def parse(self, source: EvidenceSource, ctx: Context, errors: ErrorSink) -> Iterator[Event]:
        from dissect.eventlog.evtx import Evtx

        zero_filled: list[str] = []
        for path in (p for pattern in self.patterns(source) for p in source.glob(pattern)):
            try:
                fh = source.open(path)
            except Exception as exc:
                errors(self.meta.name, f"{path}: cannot open: {exc}")
                continue
            with fh:
                header = fh.read(EVTX_HEADER_SIZE)
                if header[:8] != b"ElfFile\x00":
                    if header and not header.strip(b"\0"):
                        zero_filled.append(path)
                    else:
                        errors(self.meta.name, f"{path}: not a valid EVTX file (bad header signature)")
                    continue
                problem = truncation_problem(header, fh.seek(0, 2))
                if problem:
                    errors(self.meta.name, f"{path}: truncated or damaged ({problem}); parsing what is readable")
                fh.seek(0)
                try:
                    records = iter(Evtx(fh))
                except Exception as exc:
                    errors(self.meta.name, f"{path}: {type(exc).__name__}: {exc}")
                    continue
                bad = 0
                while True:
                    try:
                        record = next(records)
                    except StopIteration:
                        break
                    except Exception as exc:
                        errors(self.meta.name, f"{path}: stopped reading: {type(exc).__name__}: {exc}")
                        break
                    try:
                        event = record_to_event(dict(record), path)
                    except Exception as exc:
                        bad += 1
                        if bad <= 5:
                            errors(self.meta.name, f"{path}: bad record: {type(exc).__name__}: {exc}")
                        continue
                    if event is not None:
                        yield event
        if zero_filled:
            errors(self.meta.name,
                   f"{len(zero_filled)} EVTX file(s) are zero-filled and were skipped (typical for shadow copies: "
                   f"Windows did not preserve them), e.g. {zero_filled[0]}")
