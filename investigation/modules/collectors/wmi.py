"""WMI / Task Scheduler live-data collectors. Windows-only imports are lazy so this module imports anywhere."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from investigation.core.registry import register
from investigation.core.requirements import Context
from investigation.modules.collectors.base import VolatileCollector
from investigation.modules.collectors.live import _meta

log = logging.getLogger("investigation.collect.wmi")


class WmiUnavailable(RuntimeError):
    """The WMI namespace or class does not exist (or WMI/COM is not usable)."""


def _com_init() -> None:
    import pythoncom

    pythoncom.CoInitialize()


def wmi_query(namespace: str, wmi_class: str, properties: Sequence[str]) -> list[dict[str, Any]]:
    _com_init()
    try:
        import win32com.client

        svc = win32com.client.GetObject(f"winmgmts:{{impersonationLevel=impersonate}}!\\\\.\\{namespace}")
        try:
            items = list(svc.ExecQuery(f"SELECT {', '.join(properties)} FROM {wmi_class}"))
        except Exception:
            items = list(svc.ExecQuery(f"SELECT * FROM {wmi_class}"))
    except Exception as exc:
        raise WmiUnavailable(f"{namespace}\\{wmi_class}: {type(exc).__name__}: {exc}") from exc
    rows = []
    for item in items:
        row = {}
        for p in properties:
            try:
                row[p] = getattr(item, p)
            except Exception:
                row[p] = None
        rows.append(row)
    return rows


_CIM_RE = re.compile(r"^(\d{14})\.(\d{6})([+-])(\d{3})$")


def cim_to_utc(value: str | None) -> datetime | None:
    try:
        m = _CIM_RE.match(str(value))
        if not m:
            return None
        local = datetime.strptime(m.group(1), "%Y%m%d%H%M%S").replace(microsecond=int(m.group(2)))
        offset = timedelta(minutes=int(m.group(4)) * (1 if m.group(3) == "+" else -1))
        return (local - offset).replace(tzinfo=timezone.utc)
    except Exception:
        return None


@dataclass(frozen=True)
class WmiTable:
    namespace: str
    wmi_class: str
    columns: dict[str, str]
    datetime_columns: tuple[str, ...] = ()
    priority: int = 50


_CIMV2 = "root\\cimv2"
_STD = "root\\StandardCimv2"

WMI_TABLES: dict[str, WmiTable] = {
    "dns_cache": WmiTable(_STD, "MSFT_DNSClientCache", {"entry": "Entry", "name": "Name", "type": "Type",
                                                        "data": "Data", "ttl": "TimeToLive"}, (), 15),
    "arp": WmiTable(_STD, "MSFT_NetNeighbor", {"ip": "IPAddress", "mac": "LinkLayerAddress", "state": "State",
                                               "interface": "InterfaceAlias"}, (), 15),
    "routes": WmiTable(_STD, "MSFT_NetRoute", {"destination": "DestinationPrefix", "next_hop": "NextHop",
                                               "metric": "RouteMetric", "interface": "InterfaceAlias"}, (), 25),
    "logon_sessions": WmiTable(_CIMV2, "Win32_LogonSession", {
        "logon_id": "LogonId", "logon_type": "LogonType", "auth_package": "AuthenticationPackage",
        "start_time_utc": "StartTime"}, ("start_time_utc",), 30),
    "services": WmiTable(_CIMV2, "Win32_Service", {
        "name": "Name", "display_name": "DisplayName", "state": "State", "start_mode": "StartMode",
        "path": "PathName", "account": "StartName", "pid": "ProcessId"}, (), 35),
    "drivers": WmiTable(_CIMV2, "Win32_SystemDriver", {
        "name": "Name", "display_name": "DisplayName", "state": "State", "start_mode": "StartMode",
        "path": "PathName"}, (), 35),
    "smb_shares": WmiTable(_CIMV2, "Win32_Share", {"name": "Name", "path": "Path", "description": "Description",
                                                   "type": "Type"}, (), 45),
    "smb_sessions": WmiTable("root\\Microsoft\\Windows\\SMB", "MSFT_SmbSession", {
        "client": "ClientComputerName", "user": "ClientUserName", "open_files": "NumOpens",
        "seconds": "SecondsExists"}, (), 45),
    "firewall_rules": WmiTable(_STD, "MSFT_NetFirewallRule", {
        "name": "Name", "display_name": "DisplayName", "enabled": "Enabled", "direction": "Direction",
        "action": "Action", "profile": "Profiles"}, (), 50),
    "hotfixes": WmiTable(_CIMV2, "Win32_QuickFixEngineering", {
        "id": "HotFixID", "description": "Description", "installed_on": "InstalledOn",
        "installed_by": "InstalledBy"}, (), 70),
}


def _table_rows(table: WmiTable) -> Iterable[Mapping[str, Any]]:
    for item in wmi_query(table.namespace, table.wmi_class, list(table.columns.values())):
        row: dict[str, Any] = {}
        for col, prop in table.columns.items():
            try:
                v = item.get(prop)
                row[col] = cim_to_utc(v) if col in table.datetime_columns else v
            except Exception:
                row[col] = None
        yield row


_MODULE_NAMES = {"services": "live_services"}


def _make_table_class(key: str, table: WmiTable) -> type[VolatileCollector]:
    def rows(self, ctx: Context) -> Iterable[Mapping[str, Any]]:
        return _table_rows(table)

    def collect(self, ctx: Context, out_dir: Path) -> int:
        _com_init()
        return VolatileCollector.collect(self, ctx, out_dir)

    name = "".join(p.capitalize() for p in key.split("_"))
    cls = type(name, (VolatileCollector,), {
        "meta": _meta(_MODULE_NAMES.get(key, key), f"WMI {table.wmi_class}", table.priority),
        "filename": f"{key}.csv", "columns": tuple(table.columns),
        "rows": rows, "collect": collect,
        "__module__": __name__, "__qualname__": name,
    })
    return register(cls)


WMI_TABLES_CLASSES: dict[str, type[VolatileCollector]] = {k: _make_table_class(k, t) for k, t in WMI_TABLES.items()}
globals().update({c.__name__: c for c in WMI_TABLES_CLASSES.values()})


def _com_collect(self: VolatileCollector, ctx: Context, out_dir: Path) -> int:
    _com_init()
    return VolatileCollector.collect(self, ctx, out_dir)


@register
class WmiSubscriptions(VolatileCollector):
    meta = _meta("wmi_subscriptions", "WMI event subscriptions (persistence)", 50)
    filename = "wmi_subscriptions.csv"
    columns = ("kind", "name", "detail")
    collect = _com_collect

    def rows(self, ctx: Context) -> Iterable[Mapping[str, Any]]:
        ns = "root\\subscription"
        specs = (
            ("__EventFilter", ["Name", "Query"], lambda r: (r.get("Name"), r.get("Query"))),
            ("CommandLineEventConsumer", ["Name", "CommandLineTemplate", "ExecutablePath"],
             lambda r: (r.get("Name"), r.get("CommandLineTemplate") or r.get("ExecutablePath"))),
            ("ActiveScriptEventConsumer", ["Name", "ScriptFileName", "ScriptText"],
             lambda r: (r.get("Name"), r.get("ScriptFileName") or str(r.get("ScriptText") or "")[:2000])),
            ("__FilterToConsumerBinding", ["Filter", "Consumer"], lambda r: (r.get("Filter"), r.get("Consumer"))),
        )
        failed = 0
        for cls, props, pick in specs:
            try:
                found = wmi_query(ns, cls, props)
            except WmiUnavailable as exc:
                failed += 1
                yield {"kind": cls, "name": "", "detail": f"unavailable: {exc}"}
                continue
            for r in found:
                name, detail = pick(r)
                yield {"kind": cls, "name": name, "detail": detail}
        if failed == len(specs):
            raise WmiUnavailable("all subscription classes unavailable")


@register
class Defender(VolatileCollector):
    meta = _meta("defender", "Microsoft Defender status and exclusions", 55)
    filename = "defender.csv"
    columns = ("key", "value")
    collect = _com_collect

    def rows(self, ctx: Context) -> Iterable[Mapping[str, Any]]:
        ns = "root\\Microsoft\\Windows\\Defender"
        failed = 0
        for cls, props in (
            ("MSFT_MpComputerStatus", ["AMRunningMode", "RealTimeProtectionEnabled", "AntivirusEnabled",
                                       "AntivirusSignatureLastUpdated", "TamperProtectionSource"]),
            ("MSFT_MpPreference", ["ExclusionPath", "ExclusionProcess", "ExclusionExtension",
                                   "DisableRealtimeMonitoring"]),
        ):
            try:
                found = wmi_query(ns, cls, props)
            except WmiUnavailable as exc:
                failed += 1
                yield {"key": cls, "value": f"unavailable: {exc}"}
                continue
            for r in found:
                for p in props:
                    v = r.get(p)
                    yield {"key": p, "value": (cim_to_utc(v) or v) if p == "AntivirusSignatureLastUpdated"
                           and isinstance(v, str) else v}
        if failed == 2:
            raise WmiUnavailable("all Defender classes unavailable")


def _schedule_service() -> Any:
    import win32com.client

    svc = win32com.client.Dispatch("Schedule.Service")
    svc.Connect()
    return svc


def _task_time(v: Any) -> datetime | None:
    if not isinstance(v, datetime) or v.year < 1980:
        return None
    return v.replace(tzinfo=None).astimezone().astimezone(timezone.utc)


def _walk(folder: Any) -> Iterable[tuple[str, Any]]:
    """Yield ("task", task) or ("error", (folder_path, message)); one bad folder never stops the walk."""
    try:
        path = str(folder.Path)
    except Exception:
        path = ""
    try:
        tasks = list(folder.GetTasks(1))
    except Exception as exc:
        log.warning("task folder %s GetTasks failed: %s", path, exc)
        yield "error", (path, f"{type(exc).__name__}: {exc}")
        tasks = []
    for t in tasks:
        yield "task", t
    try:
        subs = list(folder.GetFolders(0))
    except Exception as exc:
        log.warning("task folder %s GetFolders failed: %s", path, exc)
        yield "error", (path, f"{type(exc).__name__}: {exc}")
        subs = []
    for sub in subs:
        yield from _walk(sub)


def _try(fn: Any, default: Any = "") -> Any:
    try:
        return fn()
    except Exception:
        return default


@register
class Tasks(VolatileCollector):
    meta = _meta("live_tasks", "Scheduled tasks", 40)
    filename = "tasks.csv"
    columns = ("path", "name", "state", "enabled", "last_run_utc", "next_run_utc", "last_result", "actions",
               "author")
    collect = _com_collect

    def rows(self, ctx: Context) -> Iterable[Mapping[str, Any]]:
        svc = _schedule_service()
        for kind, item in _walk(svc.GetFolder("\\")):
            if kind == "error":
                yield {"path": item[0], "name": "", "state": f"error: {item[1]}"}
                continue
            t = item
            yield {
                "path": _try(lambda: t.Path), "name": _try(lambda: t.Name), "state": _try(lambda: t.State),
                "enabled": _try(lambda: t.Enabled), "last_run_utc": _try(lambda: _task_time(t.LastRunTime), None),
                "next_run_utc": _try(lambda: _task_time(t.NextRunTime), None),
                "last_result": _try(lambda: t.LastTaskResult),
                "actions": _try(lambda: [f"{a.Path} {a.Arguments}".strip()
                                         for a in t.Definition.Actions if a.Type == 0], []),
                "author": _try(lambda: t.Definition.RegistrationInfo.Author),
            }
