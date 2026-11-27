from datetime import datetime, timezone

import pytest

from investigation.core.models import Event
from investigation.core.requirements import Context
from investigation.core.store import EventStore
from investigation.modules.detections.builtin import BuiltinRules
from investigation.modules.detections.process_tree import ProcessTree

T0 = datetime(2024, 5, 1, tzinfo=timezone.utc)
_n = [0]


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))


def proc(pid, ppid, name, exit_time=None, tags=()):
    return Event(timestamp=T0, timestamp_desc="Process Created", artifact="memory_process", source_file="m",
                 message=name, fields={"PID": pid, "PPID": ppid, "ImageFileName": name, "ExitTime": exit_time},
                 tags=tags)


NORMAL = [proc(4, 0, "System"), proc(300, 4, "smss.exe"), proc(500, 400, "wininit.exe"),
          proc(600, 500, "services.exe"), proc(700, 500, "lsass.exe"), proc(800, 600, "svchost.exe"),
          proc(1000, 900, "explorer.exe")]


def tree_ids(tmp_path, events):
    _n[0] += 1
    store = EventStore(tmp_path / f"t{_n[0]}.db")
    store.add_many(events)
    return {f.rule_id for f in ProcessTree().detect(store, Context())}


def test_normal_tree_is_clean(tmp_path):
    assert tree_ids(tmp_path, NORMAL) == set()


def test_unexpected_parent(tmp_path):
    assert "INV-PROC-001" in tree_ids(tmp_path, NORMAL + [proc(1200, 1000, "lsass.exe")])
    assert "INV-PROC-001" in tree_ids(tmp_path, NORMAL + [proc(1300, 1000, "svchost.exe")])


def test_two_lsass(tmp_path):
    assert "INV-PROC-002" in tree_ids(tmp_path, NORMAL + [proc(1200, 500, "lsass.exe")])
    exited = proc(1200, 500, "lsass.exe", exit_time="2024-05-01T09:00:00+00:00")
    assert "INV-PROC-002" not in tree_ids(tmp_path, NORMAL + [exited])


def test_lsass_child(tmp_path):
    assert "INV-PROC-003" in tree_ids(tmp_path, NORMAL + [proc(1400, 700, "cmd.exe")])


def test_hidden(tmp_path):
    assert "INV-PROC-004" in tree_ids(tmp_path, NORMAL + [proc(6666, 800, "evil.exe", tags=("hidden_or_exited",))])


def mem(artifact, **fields):
    return Event(timestamp=T0, timestamp_desc="t", artifact=artifact, source_file="m", message="m", fields=fields)


def rule_ids(tmp_path, *events):
    _n[0] += 1
    store = EventStore(tmp_path / f"r{_n[0]}.db")
    store.add_many(events)
    return {f.rule_id for f in BuiltinRules().detect(store, Context())}


@pytest.mark.parametrize("rule,pos,neg", [
    ("INV-MEM-001",
     mem("memory_malfind", Protection="PAGE_EXECUTE_READWRITE", Hexdump="4d 5a 90 00", Disasm="dec ebp"),
     mem("memory_malfind", Protection="PAGE_EXECUTE_READWRITE", Hexdump="fc 48 83 e4", Disasm="cld")),
    ("INV-MEM-002", mem("memory_cmdline", Args="powershell -nop -w hidden -enc SQBFAFgA"),
     mem("memory_cmdline", Args="svchost.exe -k netsvcs")),
    ("INV-MEM-003", mem("memory_process", ImageFileName="svch0st.exe"), mem("memory_process", ImageFileName="svchost.exe")),
    ("INV-MEM-004", mem("memory_network", Owner="rundll32.exe", ForeignAddr="185.220.101.5", State="ESTABLISHED"),
     mem("memory_network", Owner="chrome.exe", ForeignAddr="142.250.1.1", State="ESTABLISHED")),
    ("INV-MEM-004", mem("memory_network", Owner="rundll32.exe", ForeignAddr="185.220.101.5", State="ESTABLISHED"),
     mem("memory_network", Owner="rundll32.exe", ForeignAddr="192.168.1.10", State="ESTABLISHED")),
    ("INV-MEM-005", mem("memory_service", Binary=r"C:\Users\Public\upd.exe"),
     mem("memory_service", Binary=r"C:\Windows\System32\svchost.exe -k netsvcs")),
])
def test_memory_rules(tmp_path, rule, pos, neg):
    assert rule in rule_ids(tmp_path, pos)
    assert rule not in rule_ids(tmp_path, neg)
