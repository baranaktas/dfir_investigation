import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from investigation import cli as cli_mod
from investigation.core import package as package_mod
from investigation.core.collect import collect
from investigation.core.models import Event
from investigation.core.module import CollectorModule, ModuleMeta, ModuleType
from investigation.core.package import MANIFEST_NAME, write_manifest
from investigation.core.registry import ModuleRegistry
from investigation.core.requirements import Context
from investigation.core.store import EventStore
from investigation.modules.collectors import files, wmi
from investigation.modules.collectors.base import read_csv, write_csv
from investigation.modules.detections.process_tree import ProcessTree
from investigation.modules.parsers.live import LiveParser

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))


def test_csv_cell_with_lone_surrogate(tmp_path):
    p = tmp_path / "x.csv"
    write_csv(p, ["a", "b"], [{"a": "bad\udc80name", "b": "ok"}, {"a": "next", "b": "row"}])
    rows = list(read_csv(p))
    assert len(rows) == 2 and rows[1]["a"] == "next" and "\\udc80" in rows[0]["a"]


def test_manifest_surrogate_in_info_and_extra(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    write_manifest(tmp_path, {"hostname": "h", "warnings": ["bad\udc80"]}, {"a.txt": {"source_path": "C:\\\udc80"}})
    m = json.loads((tmp_path / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert m["files"][0]["source_path"] == "C:\\\udc80"


def test_manifest_fallback_always_written(tmp_path, monkeypatch):
    (tmp_path / "a.txt").write_text("x")
    monkeypatch.setattr(package_mod, "hash_file", lambda p: (_ for _ in ()).throw(OSError("boom")))
    path = write_manifest(tmp_path, {"hostname": "h", "status": "complete", "warnings": ["w"]})
    m = json.loads(path.read_text(encoding="utf-8"))
    assert m["status"] == "partial" and m["files"] == [] and m["format_version"]
    assert m["warnings"][0] == "w" and "boom" in m["warnings"][1]


def test_collected_file_name_with_surrogate_manifest(tmp_path):
    root = tmp_path / "pkg"
    root.mkdir()
    name = "f\udc80.txt"
    try:
        (root / name).write_text("x")
    except (OSError, UnicodeEncodeError):
        pytest.skip("filesystem rejects lone surrogates")
    write_manifest(root, {"hostname": "h"})
    assert (root / MANIFEST_NAME).is_file()


def test_collect_does_not_load_user_plugins(tmp_path, capsys):
    mods = tmp_path / "home" / "modules"
    mods.mkdir(parents=True)
    marker = tmp_path / "loaded"
    (mods / "evil.py").write_text(f"open({str(marker)!r}, 'w').write('x')\n")
    assert cli_mod.main(["collect", "--only", "nonsense"]) == 2
    assert not marker.exists()


def test_collect_unknown_selection_keyerror_is_usage_error(monkeypatch, capsys):
    def boom(*a, **k):
        raise KeyError("unknown collector or category 'zzz'")

    monkeypatch.setattr(cli_mod, "collect", boom)
    monkeypatch.setattr(cli_mod, "list_volumes", lambda: [])
    assert cli_mod.main(["collect", "--only", "live"]) == 2
    assert "zzz" in capsys.readouterr().err


def test_win_long_path():
    assert files.win_long_path(Path("/x/y"), os_name="posix") == str(Path("/x/y"))
    assert files.win_long_path(Path("C:/a/b"), os_name="nt") == "\\\\?\\C:\\a\\b"
    assert files.win_long_path("\\\\srv\\share\\f", os_name="nt") == "\\\\?\\UNC\\srv\\share\\f"
    assert files.win_long_path("\\\\?\\C:\\a", os_name="nt") == "\\\\?\\C:\\a"


def test_safe_component_encoding():
    sc = files.safe_component
    assert sc("CON") == "%43ON" and sc("nul.txt") == "%6Eul.txt" and sc("Com1") == "%43om1"
    assert sc("LPT9.log") == "%4CPT9.log" and sc("console") == "console" and sc("COM10") == "COM10"
    assert sc("name.") == "name%2E" and sc("name ") == "name%20" and sc("a. .") == "a%2E%20%2E"
    assert files.safe_key("Users/x/NUL/f.:s") == "Users/x/%4EUL/f.%3As"
    assert files.safe_key("a/b:c") == "a/b%3Ac"


def test_one_records_original_name(tmp_path):
    class R:
        def is_dir(self, p): return False
        def stat(self, p): return 1, None
        def open(self, p):
            import io
            return io.BytesIO(b"abc")

    extra = {}
    assert files.FilesCollector._one(R(), "C", "Users/NUL", tmp_path, extra) == 1
    (key, entry), = extra.items()
    assert key == "files/C/Users/%4EUL" and entry["original_name"] == "Users/NUL"
    assert (tmp_path / key).read_bytes() == b"abc"


def _proc(artifact, pid, ppid, name, ts):
    return Event(timestamp=ts, timestamp_desc="Process Started" if artifact == "live_process" else "Process Created",
                 artifact=artifact, source_file="m", message=name,
                 fields={"PID": pid, "PPID": ppid, "ImageFileName": name, "ExitTime": "",
                         "CreateTime": ts.isoformat()})


@pytest.mark.parametrize("artifact", ["live_process", "memory_process"])
def test_pid_reuse_not_flagged(tmp_path, artifact):
    later = datetime(2026, 1, 5, tzinfo=timezone.utc)
    evs = [_proc(artifact, 4, 0, "System", T0), _proc(artifact, 300, 4, "smss.exe", T0),
           _proc(artifact, 500, 300, "csrss.exe", T0)]
    wrong = evs[:2] + [_proc(artifact, 500, 777, "csrss.exe", T0), _proc(artifact, 777, 1, "notepad.exe", later)]
    store = EventStore(tmp_path / "a.db")
    store.add_many(wrong)
    assert {f.rule_id for f in ProcessTree().detect(store, Context())} == set()
    bad = evs[:2] + [_proc(artifact, 500, 777, "csrss.exe", later), _proc(artifact, 777, 1, "notepad.exe", T0)]
    store2 = EventStore(tmp_path / "b.db")
    store2.add_many(bad)
    assert "INV-PROC-001" in {f.rule_id for f in ProcessTree().detect(store2, Context())}


def test_task_time_local_wall_clock():
    labelled_utc = datetime(2026, 11, 26, 10, 0, tzinfo=timezone.utc)
    expect = datetime(2026, 11, 26, 10, 0).astimezone().astimezone(timezone.utc)
    assert wmi._task_time(labelled_utc) == expect
    assert wmi._task_time(datetime(2026, 11, 26, 10, 0)) == expect
    assert wmi._task_time(datetime(1899, 12, 30)) is None


class _Logs(CollectorModule):
    meta = ModuleMeta(name="logs", description="d", type=ModuleType.COLLECTOR, platforms=("any",), category="live")

    def collect(self, ctx, out_dir):
        wmi.log.warning("collector says hi")
        return []


def test_collector_warning_in_log_and_no_duplicate_console(tmp_path):
    seen = []

    class H(logging.Handler):
        def emit(self, record):
            seen.append(record.getMessage())

    h = H(logging.INFO)
    logging.getLogger().addHandler(h)
    try:
        reg = ModuleRegistry(fresh=True)
        reg.add(_Logs)
        res = collect(None, out=tmp_path, registry=reg)
    finally:
        logging.getLogger().removeHandler(h)
    assert "collector says hi" in (res.root / "collection.log").read_text(encoding="utf-8")
    assert seen == []
    assert logging.getLogger("investigation.collect").propagate is True


def test_defender_na_exclusion_ignored(tmp_path):
    from investigation.modules.detections.live_rules import LiveRules
    ev = Event(timestamp=T0, timestamp_desc="x", artifact="live_defender", source_file="v", message="m",
               fields={"key": "ExclusionPath", "value": "N/A: Must be an administrator to view exclusions"})
    store = EventStore(tmp_path / "d.db")
    store.add_many([ev])
    assert list(LiveRules().detect(store, Context())) == []


def test_task_message_has_no_duplicated_name(tmp_path):
    (tmp_path / "volatile").mkdir()
    write_csv(tmp_path / "volatile/tasks.csv", ("name", "path", "state", "enabled", "actions"),
              [{"name": "t", "path": "\\Sub\\t", "state": "Ready", "enabled": "true", "actions": "a.exe"}])
    src = SimpleNamespace(package_root=tmp_path, manifest={"started_utc": "2026-11-26T10:00:00+00:00"})
    (e,) = list(LiveParser().parse(src, Context(), lambda m, t: None))
    assert e.message.startswith("\\Sub\\t [Ready]")


def test_scheduled_tasks_reach_four_levels():
    paths = next(t["paths"] for t in files.load_targets() if t["name"] == "scheduled_tasks")
    assert "Windows/System32/Tasks/*/*/*" in paths and "Windows/System32/Tasks/*/*/*/*" in paths


@pytest.mark.parametrize("artifact", ["live_process", "memory_process"])
def test_expected_parent_kept_despite_clock_change(tmp_path, artifact):
    boot = datetime(2026, 11, 26, 11, 29, tzinfo=timezone.utc)
    after_change = datetime(2026, 11, 26, 0, 34, tzinfo=timezone.utc)
    evs = [_proc(artifact, 4, 0, "System", boot), _proc(artifact, 300, 4, "smss.exe", boot),
           _proc(artifact, 632, 528, "wininit.exe", boot), _proc(artifact, 768, 632, "services.exe", boot),
           _proc(artifact, 9184, 768, "svchost.exe", after_change)]
    store = EventStore(tmp_path / "c.db")
    store.add_many(evs)
    assert "INV-PROC-001" not in {f.rule_id for f in ProcessTree().detect(store, Context())}


def test_backslash_in_ntfs_name_cannot_escape(tmp_path):
    key = files.safe_key("Users/..\\..\\..\\Windows\\evil.dll")
    assert "\\" not in key and ".." not in key.split("/")
    assert files.inside(tmp_path, tmp_path / "files" / "C" / key)


def test_inside_rejects_escaping_paths(tmp_path):
    assert files.inside(tmp_path, tmp_path / "files" / "C" / "a")
    assert not files.inside(tmp_path, tmp_path / ".." / "x")
    assert not files.inside(tmp_path / "pkg", tmp_path / "pkg2" / "x")
