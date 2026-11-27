"""Parse the CSVs of a live collection package (volatile/*.csv) into events.

CSV cells are attacker-controlled data: they are only ever substituted into the fixed message templates below.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from investigation.core.models import Event, EvidenceType
from investigation.core.module import ErrorSink, ModuleMeta, ModuleType, ParserModule
from investigation.core.registry import register
from investigation.core.requirements import Context
from investigation.core.source import EvidenceSource
from investigation.modules.collectors.base import read_csv

log = logging.getLogger("investigation")
OBSERVED = "Observed at Collection"
MAX_ROW_ERRORS = 5


@dataclass(frozen=True)
class LiveSpec:
    artifact: str
    evidence_type: EvidenceType
    message: str
    time_column: str | None = None
    time_desc: str = OBSERVED


E = EvidenceType
LIVE_SPECS: dict[str, LiveSpec] = {
    "processes": LiveSpec("live_process", E.EXECUTION, "{name} pid={pid} ppid={ppid}: {cmdline}",
                          "create_time_utc", "Process Started"),
    "network": LiveSpec("live_network", E.NETWORK,
                        "{proto} {local_addr}:{local_port} -> {remote_addr}:{remote_port} {state} ({process})"),
    "dns_cache": LiveSpec("live_dns", E.NETWORK, "{name} {type} {data} (ttl {ttl})"),
    "arp": LiveSpec("live_arp", E.NETWORK, "{ip} {mac} {state} ({interface})"),
    "routes": LiveSpec("live_route", E.NETWORK, "{destination} via {next_hop} metric={metric} ({interface})"),
    "sessions": LiveSpec("live_session", E.AUTHENTICATION, "{user} {terminal} from {host}", "started_utc",
                         "Session Started"),
    "logon_sessions": LiveSpec("live_logon", E.AUTHENTICATION,
                               "logon_id={logon_id} type={logon_type} {auth_package}", "start_time_utc",
                               "Logon Session Started"),
    "services": LiveSpec("live_service", E.PERSISTENCE,
                         "{name} ({display_name}) {state} {start_mode} {path} as {account}"),
    "drivers": LiveSpec("live_driver", E.PERSISTENCE, "{name} ({display_name}) {state} {start_mode} {path}"),
    "tasks": LiveSpec("live_task", E.PERSISTENCE, "{path} [{state}] enabled={enabled}: {actions}",
                      "last_run_utc", "Last Run"),
    "wmi_subscriptions": LiveSpec("live_wmi_subscription", E.PERSISTENCE, "{kind} {name}: {detail}"),
    "dlls": LiveSpec("live_dll", E.EXECUTION, "{process} pid={pid} loaded {path}"),
    "pipes": LiveSpec("live_pipe", E.OTHER, "{name}"),
    "smb_shares": LiveSpec("live_smb", E.NETWORK, "share {name} -> {path} ({description})"),
    "smb_sessions": LiveSpec("live_smb", E.NETWORK, "session {user}@{client} opens={open_files} for {seconds}s"),
    "firewall_rules": LiveSpec("live_firewall", E.NETWORK,
                               "{display_name} {direction} {action} enabled={enabled} profile={profile}"),
    "hotfixes": LiveSpec("live_hotfix", E.OTHER, "{id} {description} by {installed_by}", "installed_on",
                         "Installed"),
    "defender": LiveSpec("live_defender", E.OTHER, "{key} = {value}"),
    "env": LiveSpec("live_env", E.OTHER, "{scope} {name}={value}"),
}


class _Default(dict):
    def __missing__(self, key: str) -> str:
        return ""


_FORMATS = ("%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y", "%Y%m%d")


def _parse_time(value: str | None) -> datetime | None:
    value = (value or "").strip()
    if not value:
        return None
    dt = None
    for parse in (datetime.fromisoformat, *(lambda v, f=f: datetime.strptime(v, f) for f in _FORMATS)):
        try:
            dt = parse(value)
            break
        except ValueError:
            continue
    if dt is None or dt.year < 1980:
        return None
    try:
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        return None


def _int(value: str | None) -> int | None:
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def _csv_path(root: Path, name: str) -> Path | None:
    """volatile/<name> when it is a regular file that resolves inside the package (no symlinks)."""
    p = root / "volatile" / name
    try:
        if p.is_symlink() or (root / "volatile").is_symlink() or not p.is_file():
            return None
        return p if p.resolve().is_relative_to(root.resolve()) else None
    except OSError:
        return None


def _collection_start(source: Any, root: Path) -> datetime:
    started = _parse_time(str((getattr(source, "manifest", None) or {}).get("started_utc") or ""))
    if started:
        return started
    mtimes = []
    for name in (f"{k}.csv" for k in LIVE_SPECS):
        p = _csv_path(root, name)
        if p:
            try:
                mtimes.append(p.stat().st_mtime)
            except OSError:
                pass
    return datetime.fromtimestamp(min(mtimes), timezone.utc) if mtimes else datetime.now(timezone.utc)


@register
class LiveParser(ParserModule):
    meta = ModuleMeta(
        name="live",
        description="Live collection CSVs (processes, network, services, tasks, WMI, Defender ...)",
        type=ModuleType.PARSER,
        artifacts=tuple(dict.fromkeys(s.artifact for s in LIVE_SPECS.values())),
    )

    def parse(self, source: EvidenceSource, ctx: Context, errors: ErrorSink) -> Iterator[Event]:
        root = getattr(source, "package_root", None)
        if root is None:
            return
        root = Path(root)
        started = _collection_start(source, root)
        for key, spec in LIVE_SPECS.items():
            path = _csv_path(root, f"{key}.csv")
            if path is None:
                continue
            bad = 0
            try:
                for n, row in enumerate(read_csv(path), 2):
                    try:
                        yield self._event(row, spec, started, f"volatile/{key}.csv")
                    except Exception as exc:
                        bad += 1
                        if bad <= MAX_ROW_ERRORS:
                            errors(self.meta.name, f"{key}.csv row {n}: {type(exc).__name__}: {exc}")
                if bad > MAX_ROW_ERRORS:
                    errors(self.meta.name, f"{bad - MAX_ROW_ERRORS} more rows failed in {key}.csv")
            except Exception as exc:
                errors(self.meta.name, f"{key}.csv: {type(exc).__name__}: {exc}")

    @staticmethod
    def _event(row: dict[str, Any], spec: LiveSpec, started: datetime, source_file: str) -> Event:
        fields = {k: v for k, v in row.items() if k is not None and isinstance(v, str)}
        ts = _parse_time(fields.get(spec.time_column)) if spec.time_column else None
        desc = spec.time_desc if ts else OBSERVED
        if spec.artifact == "live_process":
            fields.update(PID=_int(fields.get("pid")), PPID=_int(fields.get("ppid")),
                          ImageFileName=fields.get("name", ""), ExitTime="")
        return Event(
            timestamp=ts or started, timestamp_desc=desc, artifact=spec.artifact, source_file=source_file,
            message=spec.message.format_map(_Default(fields))[:500], fields=fields,
            user=fields.get("user") or None, evidence_type=spec.evidence_type,
        )
