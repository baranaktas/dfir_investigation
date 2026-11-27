import csv
from datetime import datetime, timezone

import pytest

from investigation.core import collect as collect_mod
from investigation.core.collect import collect
from investigation.core.preflight import PreflightReport
from investigation.core.registry import ModuleRegistry
from investigation.modules.collectors import live, wmi


def _rows(path):
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def test_cim_to_utc():
    assert wmi.cim_to_utc("20261126133000.000000+180") == datetime(2026, 11, 26, 10, 30, tzinfo=timezone.utc)
    assert wmi.cim_to_utc("20261126133000.000000-060") == datetime(2026, 11, 26, 14, 30, tzinfo=timezone.utc)
    assert wmi.cim_to_utc(None) is None
    assert wmi.cim_to_utc("bozuk") is None


def test_wmi_tables_register_one_module_each():
    reg = ModuleRegistry(fresh=True)
    reg.discover(user_dir=None, entry_points=False)
    for key in wmi.WMI_TABLES:
        cls = reg.get(wmi._MODULE_NAMES.get(key, key))
        assert cls.meta.category == "live" and cls.filename == f"{key}.csv"
        assert cls.__module__ == wmi.__name__
    for key in ("wmi_subscriptions", "defender", "live_tasks"):
        assert reg.get(key).meta.category == "live"
    assert len(wmi.WMI_TABLES) == 10


def test_wmi_table_writes_mapped_columns(monkeypatch, tmp_path):
    monkeypatch.setattr(wmi, "_com_init", lambda: None)
    calls = []

    def fake(ns, cls, props):
        calls.append((ns, cls, list(props)))
        return [{"Name": "svc", "DisplayName": "Svc", "State": "Running", "StartMode": "Auto",
                 "PathName": "C:\\s.exe", "StartName": "LocalSystem", "ProcessId": 4}]

    monkeypatch.setattr(wmi, "wmi_query", fake)
    n = wmi.Services().collect(None, tmp_path)
    assert n == 1
    assert calls[0][:2] == ("root\\cimv2", "Win32_Service")
    (row,) = _rows(tmp_path / "volatile" / "services.csv")
    assert list(row) == ["name", "display_name", "state", "start_mode", "path", "account", "pid"]
    assert row["name"] == "svc" and row["pid"] == "4" and row["account"] == "LocalSystem"


def test_wmi_table_datetime_and_bad_row(monkeypatch, tmp_path):
    monkeypatch.setattr(wmi, "_com_init", lambda: None)
    monkeypatch.setattr(wmi, "wmi_query", lambda ns, c, p: [
        {"LogonId": "1", "StartTime": "20261126133000.000000+180"},
        {"LogonId": "2", "StartTime": "junk"},
    ])
    wmi.LogonSessions().collect(None, tmp_path)
    rows = _rows(tmp_path / "volatile" / "logon_sessions.csv")
    assert rows[0]["start_time_utc"] == "2026-11-26T10:30:00+00:00"
    assert rows[1]["start_time_utc"] == "" and rows[1]["logon_id"] == "2"


def test_wmi_unavailable_is_module_error(monkeypatch, tmp_path):
    monkeypatch.setattr(wmi, "_com_init", lambda: None)
    monkeypatch.setattr(collect_mod, "run_preflight", lambda *a, **k: PreflightReport())

    def fake(ns, cls, props):
        if cls == "MSFT_SmbSession":
            raise wmi.WmiUnavailable("no namespace")
        return []

    monkeypatch.setattr(wmi, "wmi_query", fake)
    reg = ModuleRegistry(fresh=True)
    reg.add(wmi.WMI_TABLES_CLASSES["smb_sessions"])
    reg.add(wmi.WMI_TABLES_CLASSES["services"])
    res = collect(None, out=tmp_path, registry=reg)
    st = {m["name"]: m["status"] for m in res.manifest["modules"]}
    assert st == {"live_services": "ok", "smb_sessions": "error"}


def test_wmi_subscriptions_kinds(monkeypatch, tmp_path):
    monkeypatch.setattr(wmi, "_com_init", lambda: None)
    data = {
        "__EventFilter": [{"Name": "F", "Query": "SELECT 1"}],
        "CommandLineEventConsumer": [{"Name": "C1", "CommandLineTemplate": "cmd /c x", "ExecutablePath": "e"},
                                     {"Name": "C2", "CommandLineTemplate": None, "ExecutablePath": "e.exe"}],
        "ActiveScriptEventConsumer": [{"Name": "S1", "ScriptFileName": "a.vbs", "ScriptText": "t"},
                                      {"Name": "S2", "ScriptFileName": None, "ScriptText": "x" * 3000}],
        "__FilterToConsumerBinding": [{"Filter": "f", "Consumer": "c"}],
    }

    def fake(ns, cls, props):
        assert ns == "root\\subscription"
        return data[cls]

    monkeypatch.setattr(wmi, "wmi_query", fake)
    wmi.WmiSubscriptions().collect(None, tmp_path)
    rows = _rows(tmp_path / "volatile" / "wmi_subscriptions.csv")
    got = {(r["kind"], r["name"]): r["detail"] for r in rows}
    assert got[("__EventFilter", "F")] == "SELECT 1"
    assert got[("CommandLineEventConsumer", "C1")] == "cmd /c x"
    assert got[("CommandLineEventConsumer", "C2")] == "e.exe"
    assert got[("ActiveScriptEventConsumer", "S1")] == "a.vbs"
    assert got[("ActiveScriptEventConsumer", "S2")] == "x" * 2000
    assert got[("__FilterToConsumerBinding", "f")] == "c"


def test_defender_key_values(monkeypatch, tmp_path):
    monkeypatch.setattr(wmi, "_com_init", lambda: None)

    def fake(ns, cls, props):
        if cls == "MSFT_MpComputerStatus":
            return [{"AMRunningMode": "Normal", "RealTimeProtectionEnabled": True}]
        return [{"ExclusionPath": ["C:\\a", "C:\\b"], "DisableRealtimeMonitoring": False}]

    monkeypatch.setattr(wmi, "wmi_query", fake)
    wmi.Defender().collect(None, tmp_path)
    got = {r["key"]: r["value"] for r in _rows(tmp_path / "volatile" / "defender.csv")}
    assert got["ExclusionPath"] == "C:\\a; C:\\b"
    assert got["RealTimeProtectionEnabled"] == "true" and got["AMRunningMode"] == "Normal"


class _Coll:
    def __init__(self, items):
        self._i = list(items)
        self.Count = len(self._i)

    def __iter__(self):
        return iter(self._i)


class _Action:
    def __init__(self, path, args, type_=0):
        self.Type, self.Path, self.Arguments = type_, path, args


class _Task:
    def __init__(self, name, path, actions, last=None, nxt=None):
        self.Name, self.Path, self.State, self.Enabled = name, path, 3, True
        self.LastRunTime = last
        self.NextRunTime = nxt
        self.LastTaskResult = 0
        self.Definition = type("D", (), {
            "Actions": _Coll(actions),
            "RegistrationInfo": type("R", (), {"Author": "me"})(),
        })()


class _Folder:
    def __init__(self, tasks, subs=(), path="\\", fail=False):
        self._t, self._s, self.Path, self._fail = tasks, subs, path, fail
        self.flags = []

    def GetTasks(self, flags):
        self.flags.append(flags)
        if self._fail:
            raise OSError("access denied")
        return _Coll(self._t)

    @property
    def GetFolders(self):
        return lambda flags: _Coll(self._s)


def test_tasks_recurses_folders(monkeypatch, tmp_path):
    monkeypatch.setattr(wmi, "_com_init", lambda: None)
    naive = datetime(2026, 11, 26, 10, 0)
    sub = _Folder([_Task("b", "\\Sub\\b", [_Action("x.exe", "-a"), _Action("", "", 5)],
                         last=datetime(1899, 12, 30), nxt=naive)])
    root = _Folder([_Task("a", "\\a", [_Action("c.exe", "")], last=naive)], [sub])

    class Svc:
        def Connect(self):
            pass

        def GetFolder(self, p):
            assert p == "\\"
            return root

    monkeypatch.setattr(wmi, "_schedule_service", lambda: Svc())
    wmi.Tasks().collect(None, tmp_path)
    rows = _rows(tmp_path / "volatile" / "tasks.csv")
    assert [r["path"] for r in rows] == ["\\a", "\\Sub\\b"]
    assert rows[1]["actions"] == "x.exe -a" and rows[0]["actions"] == "c.exe"
    assert rows[0]["author"] == "me" and rows[0]["enabled"] == "true"
    utc = naive.astimezone().astimezone(timezone.utc).isoformat()
    assert rows[0]["last_run_utc"] == utc and rows[0]["next_run_utc"] == ""
    assert rows[1]["last_run_utc"] == "" and rows[1]["next_run_utc"] == utc
    assert root.flags == [1] and sub.flags == [1]


def test_system_info_uses_wmi_then_falls_back(monkeypatch):
    monkeypatch.setattr(wmi, "_com_init", lambda: None)
    monkeypatch.setattr(wmi, "wmi_query", lambda ns, c, p: [
        {"Caption": "Microsoft Windows 11 Pro", "Version": "10.0.22631", "BuildNumber": "22631"}])
    got = {r["key"]: r["value"] for r in live.SystemInfo().rows(None)}
    assert got["os_caption"] == "Microsoft Windows 11 Pro"
    assert got["os_version"] == "10.0.22631" and got["os_build"] == "22631"

    def boom(*a):
        raise RuntimeError("x")

    monkeypatch.setattr(wmi, "wmi_query", boom)
    got = {r["key"]: r["value"] for r in live.SystemInfo().rows(None)}
    assert "os_caption" in got and got["os_caption"] != "Microsoft Windows 11 Pro"


def _run_tasks(monkeypatch, tmp_path, root):
    monkeypatch.setattr(wmi, "_com_init", lambda: None)
    svc = type("S", (), {"Connect": lambda s: None, "GetFolder": lambda s, p: root})()
    monkeypatch.setattr(wmi, "_schedule_service", lambda: svc)
    wmi.Tasks().collect(None, tmp_path)
    return _rows(tmp_path / "volatile" / "tasks.csv")


def test_tasks_bad_folder_does_not_lose_siblings(monkeypatch, tmp_path):
    bad = _Folder([], path="\\Bad", fail=True)
    good = _Folder([_Task("g", "\\Good\\g", [_Action("g.exe", "")])], path="\\Good")
    rows = _run_tasks(monkeypatch, tmp_path, _Folder([], [bad, good]))
    assert rows[0]["path"] == "\\Bad" and rows[0]["name"] == "" and rows[0]["state"].startswith("error: ")
    assert "access denied" in rows[0]["state"]
    assert [r["name"] for r in rows[1:]] == ["g"]


def test_tasks_partial_row_when_fields_raise(monkeypatch, tmp_path):
    class Broken(_Task):
        @property
        def Definition(self):
            raise OSError("bad xml")

        @Definition.setter
        def Definition(self, v):
            pass

        @property
        def State(self):
            raise OSError("no state")

        @State.setter
        def State(self, v):
            pass

    rows = _run_tasks(monkeypatch, tmp_path, _Folder([Broken("t", "\\t", [])]))
    assert len(rows) == 1
    assert rows[0]["name"] == "t" and rows[0]["path"] == "\\t" and rows[0]["state"] == ""
    assert rows[0]["actions"] == "" and rows[0]["author"] == ""


def test_subscriptions_one_class_failing_keeps_others(monkeypatch, tmp_path):
    monkeypatch.setattr(wmi, "_com_init", lambda: None)

    def fake(ns, cls, props):
        if cls == "CommandLineEventConsumer":
            raise wmi.WmiUnavailable("gone")
        return [{"Name": "F", "Query": "q", "Filter": "f", "Consumer": "c"}]

    monkeypatch.setattr(wmi, "wmi_query", fake)
    wmi.WmiSubscriptions().collect(None, tmp_path)
    rows = _rows(tmp_path / "volatile" / "wmi_subscriptions.csv")
    got = {r["kind"]: r for r in rows}
    assert got["CommandLineEventConsumer"]["detail"] == "unavailable: gone" and got["CommandLineEventConsumer"]["name"] == ""
    assert got["__EventFilter"]["detail"] == "q" and "__FilterToConsumerBinding" in got

    def allfail(ns, cls, props):
        raise wmi.WmiUnavailable("x")

    monkeypatch.setattr(wmi, "wmi_query", allfail)
    with pytest.raises(wmi.WmiUnavailable):
        wmi.WmiSubscriptions().collect(None, tmp_path / "2")


def test_defender_one_class_failing_and_signature_date(monkeypatch, tmp_path):
    monkeypatch.setattr(wmi, "_com_init", lambda: None)

    def fake(ns, cls, props):
        if cls == "MSFT_MpPreference":
            raise wmi.WmiUnavailable("nope")
        return [{"AntivirusSignatureLastUpdated": "20261126133000.000000+180"}]

    monkeypatch.setattr(wmi, "wmi_query", fake)
    wmi.Defender().collect(None, tmp_path)
    got = {r["key"]: r["value"] for r in _rows(tmp_path / "volatile" / "defender.csv")}
    assert got["MSFT_MpPreference"] == "unavailable: nope"
    assert got["AntivirusSignatureLastUpdated"] == "2026-11-26T10:30:00+00:00"

    monkeypatch.setattr(wmi, "wmi_query", lambda *a: (_ for _ in ()).throw(wmi.WmiUnavailable("x")))
    with pytest.raises(wmi.WmiUnavailable):
        wmi.Defender().collect(None, tmp_path / "2")


def test_system_info_wmi_none_keeps_platform_values(monkeypatch):
    monkeypatch.setattr(wmi, "wmi_query", lambda ns, c, p: [{"Caption": None, "Version": None, "BuildNumber": None}])
    monkeypatch.setattr(live.platform, "win32_ver", lambda: ("11", "10.0.22631", "", ""), raising=False)
    got = {r["key"]: r["value"] for r in live.SystemInfo().rows(None)}
    assert got["os_version"] == "10.0.22631" and got["os_build"] == "22631"
    assert got["os_caption"].startswith("Windows")


def test_firewall_rule_profile_property_name():
    assert wmi.WMI_TABLES["firewall_rules"].columns["profile"] == "Profiles"


def test_wmi_query_retries_with_select_star(monkeypatch):
    import sys
    import types

    class Item:
        Name, Action, Profiles = "r1", 2, 4

    queries = []

    class Svc:
        def ExecQuery(self, q):
            queries.append(q)
            if not q.startswith("SELECT *"):
                raise RuntimeError("Invalid query")
            return [Item()]

    client = types.SimpleNamespace(GetObject=lambda moniker: Svc())
    monkeypatch.setitem(sys.modules, "pythoncom", types.SimpleNamespace(CoInitialize=lambda: None))
    monkeypatch.setitem(sys.modules, "win32com", types.SimpleNamespace(client=client))
    monkeypatch.setitem(sys.modules, "win32com.client", client)
    rows = wmi.wmi_query("root\\StandardCimv2", "MSFT_NetFirewallRule", ["Name", "Action", "Profiles", "Missing"])
    assert rows == [{"Name": "r1", "Action": 2, "Profiles": 4, "Missing": None}]
    assert queries == ["SELECT Name, Action, Profiles, Missing FROM MSFT_NetFirewallRule",
                       "SELECT * FROM MSFT_NetFirewallRule"]


def test_wmi_query_both_forms_failing_is_unavailable(monkeypatch):
    import sys
    import types

    class Svc:
        def ExecQuery(self, q):
            raise RuntimeError("Invalid namespace")

    client = types.SimpleNamespace(GetObject=lambda moniker: Svc())
    monkeypatch.setitem(sys.modules, "pythoncom", types.SimpleNamespace(CoInitialize=lambda: None))
    monkeypatch.setitem(sys.modules, "win32com", types.SimpleNamespace(client=client))
    monkeypatch.setitem(sys.modules, "win32com.client", client)
    with pytest.raises(wmi.WmiUnavailable):
        wmi.wmi_query("root\\Nope", "X", ["A"])
