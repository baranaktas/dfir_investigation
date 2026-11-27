import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest

from investigation.core.collect import collect
from investigation.core.package import verify_manifest
from investigation.core.pipeline import analyze
from investigation.core.registry import ModuleRegistry
from investigation.core.requirements import AdminRights, CheckResult, Platform, Status
from investigation.modules.collectors import authenticode, live, wmi
from investigation.modules.collectors.files import OsReader
from investigation.modules.sources import target as target_mod
from tests.helpers.windows_tree import build_windows_tree, open_virtual_target

EVIL = "C:\\Users\\x\\AppData\\Local\\Temp\\evil.exe"


class FakeProc:
    def __init__(self, pid, ppid, name, exe):
        self.info = {"pid": pid, "ppid": ppid, "name": name, "exe": exe, "cmdline": [name], "username": "x",
                     "create_time": 1764150000.0}


def test_collect_then_analyze(tmp_path, monkeypatch):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(target_mod, "open_target", open_virtual_target)
    ok = lambda self, ctx: CheckResult("x", Status.OK, "ok", None, False)
    monkeypatch.setattr(Platform, "check", ok)
    monkeypatch.setattr(AdminRights, "check", ok)
    procs = [FakeProc(4, 0, "System", ""), FakeProc(9, 4, "evil.exe", EVIL)]
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: iter(procs))
    monkeypatch.setattr(psutil, "net_connections", lambda kind="inet": [SimpleNamespace(
        type=1, laddr=("10.0.0.1", 50000), raddr=("8.8.8.8", 443), status="ESTABLISHED", pid=9)])
    monkeypatch.setattr(live, "_sha256", lambda p: "h")
    monkeypatch.setattr(live, "is_remote_path", lambda p: False)
    monkeypatch.setattr(authenticode, "signature_status", lambda p: "unsigned")
    monkeypatch.setattr(wmi, "_com_init", lambda: None)
    monkeypatch.setattr(wmi, "wmi_query", lambda ns, c, props: [
        {"Name": "svc", "DisplayName": "Svc", "State": "Running", "StartMode": "Auto",
         "PathName": "C:\\s.exe", "StartName": "LocalSystem", "ProcessId": 4}])

    tree = build_windows_tree(tmp_path / "C")
    reg = ModuleRegistry(fresh=True)
    reg.discover(user_dir=None, entry_points=False)
    keep = {"processes", "network", "live_services", "files_raw"}
    for name in list(reg._modules):
        if reg._modules[name].meta.category in ("live", "files") and name not in keep:
            del reg._modules[name]
    collect(["live", "files"], out=tmp_path / "pk", registry=reg,
            options={"files_readers": {"C": OsReader(tree, None)}})
    pkg = next((tmp_path / "pk").iterdir())

    result = analyze(pkg, tmp_path / "out", allow_install=False)
    assert result.module_errors == []
    con = sqlite3.connect(next(Path(tmp_path / "out").glob("*.db")))
    arts = {r[0] for r in con.execute("select distinct artifact from events")}
    con.close()
    assert {"live_process", "live_network", "live_service", "prefetch"} <= arts
    findings = json.loads((tmp_path / "out" / "findings.json").read_text(encoding="utf-8"))
    ids = {f["rule_id"] for f in (findings if isinstance(findings, list) else findings.get("findings", []))}
    assert "INV-LIVE-001" in ids
    assert verify_manifest(pkg) == []

