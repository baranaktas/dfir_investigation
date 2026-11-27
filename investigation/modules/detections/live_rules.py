"""Detections over live collection data (processes, network, WMI subscriptions, Defender)."""

from __future__ import annotations

import ipaddress
from typing import Iterator

from investigation.core.models import Event, Finding, Severity
from investigation.core.module import DetectionModule, ErrorSink, ModuleMeta, ModuleType
from investigation.core.registry import register
from investigation.core.requirements import Context
from investigation.core.store import EventStore

USER_WRITABLE = ("\\appdata\\", "\\temp\\", "\\programdata\\", "\\users\\public\\", "\\downloads\\")
LOLBINS = {"powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
           "bitsadmin.exe", "wscript.exe", "cscript.exe", "msbuild.exe", "installutil.exe"}
BAD_CONSUMERS = {"CommandLineEventConsumer", "ActiveScriptEventConsumer"}


def _public(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.strip())
        return (getattr(ip, "ipv4_mapped", None) or ip).is_global
    except ValueError:
        return False


def _defender_weak(e: Event) -> bool:
    key, value = str(e.fields.get("key", "")), str(e.fields.get("value", "")).strip()
    if key == "DisableRealtimeMonitoring":
        return value.casefold() == "true"
    return key.startswith("Exclusion") and bool(value) and not value.upper().startswith("N/A")


@register
class LiveRules(DetectionModule):
    meta = ModuleMeta(
        name="live_rules",
        description="Detections on live collection data: user-writable unsigned processes, LOLBin network "
                    "connections, WMI persistence, weakened Defender",
        type=ModuleType.DETECTION,
    )

    def detect(self, store: EventStore, ctx: Context, errors: ErrorSink | None = None) -> Iterator[Finding]:
        def pick(artifact, test):
            return [e for e in store.iter_events(artifact=artifact) if test(e.fields)]

        hits = pick("live_process", lambda f: any(p in str(f.get("exe", "")).casefold() for p in USER_WRITABLE)
                    and f.get("signed") in ("unsigned", "error"))
        if hits:
            yield Finding("INV-LIVE-001", "Unsigned process running from a user-writable path", Severity.HIGH,
                          "A running process was started from AppData/Temp/ProgramData/Public/Downloads and is "
                          "not Authenticode-signed - typical of dropped malware.", ("T1204.002",), hits)
        hits = pick("live_network", lambda f: _public(str(f.get("remote_addr", "")))
                    and str(f.get("process", "")).casefold() in LOLBINS)
        if hits:
            yield Finding("INV-LIVE-002", "Living-off-the-land binary with an internet connection", Severity.HIGH,
                          "A script host or proxy-execution binary holds a connection to a public IP address - "
                          "common for download cradles and C2.", ("T1218", "T1105"), hits)
        hits = pick("live_wmi_subscription", lambda f: f.get("kind") in BAD_CONSUMERS)
        if hits:
            yield Finding("INV-LIVE-003", "WMI event consumer that runs commands or scripts", Severity.HIGH,
                          "A WMI permanent subscription with a command-line or script consumer exists - a "
                          "stealthy persistence mechanism.", ("T1546.003",), hits)
        hits = [e for e in store.iter_events(artifact="live_defender") if _defender_weak(e)]
        if hits:
            yield Finding("INV-LIVE-004", "Microsoft Defender weakened", Severity.MEDIUM,
                          "Real-time monitoring is disabled or Defender exclusions are configured.",
                          ("T1562.001",), hits)
