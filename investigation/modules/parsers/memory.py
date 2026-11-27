"""Memory analysis with Volatility 3 (run in a subprocess, JSON-lines output).

Use `investigation analyze <evidence> --memory mem.raw`, or analyze a .mem/.vmem/.dmp/.lime file directly.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from investigation.core.models import Event, EvidenceType
from investigation.core.module import ErrorSink, ModuleMeta, ModuleType, ParserModule
from investigation.core.frozen import is_frozen
from investigation.core.registry import register
from investigation.core.requirements import Context, PythonPackage
from investigation.core.source import EvidenceSource

log = logging.getLogger("investigation")
VOL_COMMAND: list[str] | None = None
DEFAULT_TIMEOUT = 1800
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
COMMAND_PROPERTY = re.compile(r"_Command_\d+$")

PLUGINS = [
    ("windows.pslist", None, "memory_process", EvidenceType.EXECUTION,
     "{ImageFileName} pid={PID} ppid={PPID}", "CreateTime", "Process Created"),
    ("windows.cmdline", None, "memory_cmdline", EvidenceType.EXECUTION, "{Process} pid={PID}: {Args}", None, None),
    ("windows.cmdscan", None, "memory_console", EvidenceType.EXECUTION, "{Process} pid={PID}: {Data}", None, None),
    ("windows.consoles", None, "memory_console", EvidenceType.EXECUTION, "{Process} pid={PID}: {Data}", None, None),
    ("windows.netscan", None, "memory_network", EvidenceType.NETWORK,
     "{Owner} pid={PID} {Proto} {LocalAddr}:{LocalPort} -> {ForeignAddr}:{ForeignPort} {State}", "Created",
     "Connection Created"),
    ("windows.malware.malfind", "windows.malfind", "memory_malfind", EvidenceType.EXECUTION,
     "{Process} pid={PID} {Protection} at {Start VPN} ({Notes})", None, None),
    ("windows.svcscan", None, "memory_service", EvidenceType.PERSISTENCE,
     "{Name} ({Display}) {State} {Binary}", None, None),
]


class VolatilityError(Exception):
    pass


def _flatten(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        children = row.pop("__children", []) or []
        out.append(row)
        out.extend(_flatten(children))
    return out


class VolatilityRunner:
    def __init__(self, image: Path, timeout: int = DEFAULT_TIMEOUT, command: list[str] | None = None):
        self.image = Path(image)
        self.timeout = timeout
        frozen_cmd = [sys.executable, "__volatility__"]
        self.command = command or VOL_COMMAND or (frozen_cmd if is_frozen() else [
            sys.executable, "-I", "-c", "import sys; from volatility3.cli import main; sys.exit(main())",
        ])

    def run(self, plugin: str) -> list[dict[str, Any]]:
        cmd = [*self.command, "-q", "-r", "jsonl", "-f", str(self.image), plugin]
        try:
            with tempfile.TemporaryDirectory(prefix="investigation-vol-") as cwd:
                proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                      timeout=self.timeout, cwd=cwd)
        except subprocess.TimeoutExpired:
            raise VolatilityError(f"{plugin} timed out after {self.timeout}s") from None
        except OSError as exc:
            raise VolatilityError(f"{plugin}: cannot start Volatility: {exc}") from None
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no output"]
            raise VolatilityError(f"{plugin} failed (exit {proc.returncode}): {tail[0][:300]}")
        rows = []
        for n, line in enumerate(proc.stdout.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                raise VolatilityError(f"{plugin}: invalid JSON on output line {n}") from None
            rows.extend(value if isinstance(value, list) else [value])
        return _flatten(rows)


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value or value == "N/A":
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


class _Default(dict):
    def __missing__(self, key: str) -> str:
        return ""


def memory_image(source: EvidenceSource, ctx: Context) -> Path | None:
    if ctx.options.get("memory"):
        return Path(ctx.options["memory"])
    return getattr(source, "memory_image", None)


@register
class MemoryParser(ParserModule):
    meta = ModuleMeta(
        name="memory",
        description="Memory image analysis with Volatility 3 (pslist/psscan, cmdline, cmdscan/consoles, netscan, malfind, svcscan)",
        type=ModuleType.PARSER,
        requirements=(PythonPackage("volatility3", "volatility3", min_version="2.7"),),
        artifacts=("memory_process", "memory_cmdline", "memory_network", "memory_malfind", "memory_service",
                   "memory_console"),
    )

    def parse(self, source: EvidenceSource, ctx: Context, errors: ErrorSink) -> Iterator[Event]:
        image = memory_image(source, ctx)
        if image is None:
            return
        if not image.is_file():
            errors(self.meta.name, f"memory image not found: {image}")
            return
        runner = VolatilityRunner(image, timeout=int(ctx.options.get("memory_timeout", DEFAULT_TIMEOUT)))
        src = image.name

        captured = None
        try:
            for row in runner.run("windows.info"):
                if row.get("Variable") == "SystemTime":
                    captured = _parse_time(row.get("Value"))
        except VolatilityError as exc:
            errors(self.meta.name, str(exc))

        pslist_pids: set[Any] = set()
        for plugin, fallback, artifact, etype, template, ts_field, ts_label in PLUGINS:
            try:
                rows = runner.run(plugin)
            except VolatilityError as exc:
                if fallback:
                    try:
                        rows = runner.run(fallback)
                    except VolatilityError:
                        errors(self.meta.name, str(exc))
                        continue
                else:
                    errors(self.meta.name, str(exc))
                    continue
            if plugin == "windows.pslist":
                pslist_pids = {r.get("PID") for r in rows}
            for row in rows:
                if artifact == "memory_console" and not (
                        COMMAND_PROPERTY.search(str(row.get("Property"))) and str(row.get("Data") or "").strip()):
                    continue
                yield self._event(row, artifact, etype, template, ts_field, ts_label, captured, f"{src}:{plugin}")

        try:
            for row in runner.run("windows.psscan"):
                if pslist_pids and row.get("PID") not in pslist_pids:
                    exited = row.get("ExitTime") not in (None, "", "N/A")
                    yield self._event(
                        row, "memory_process", EvidenceType.EXECUTION,
                        "{ImageFileName} pid={PID} ppid={PPID} (psscan only: "
                        + ("exited at {ExitTime})" if exited else "no exit time - possibly hidden)"),
                        "CreateTime", "Process Created", captured, f"{src}:windows.psscan",
                        tags=("exited",) if exited else ("hidden_or_exited",))
        except VolatilityError as exc:
            errors(self.meta.name, str(exc))

    @staticmethod
    def _event(row, artifact, etype, template, ts_field, ts_label, captured, source_file, tags=()) -> Event:
        fields = {k: v for k, v in row.items() if not isinstance(v, (dict, list))}
        ts = _parse_time(row.get(ts_field)) if ts_field else None
        desc = ts_label
        if ts is None and captured is not None:
            ts, desc = captured, "Memory Captured"
        if ts is None:
            ts, desc, tags = EPOCH, "No Timestamp", (*tags, "no_timestamp")
        return Event(
            timestamp=ts, timestamp_desc=desc, artifact=artifact, source_file=source_file,
            message=template.format_map(_Default({k: "" if v is None else v for k, v in fields.items()}))[:500],
            fields=fields, tags=tuple(tags), evidence_type=etype,
        )
