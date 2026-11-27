from datetime import datetime, timezone

import pytest

from investigation.core.models import Event
from investigation.core.requirements import Context
from investigation.core.store import EventStore
from investigation.modules.detections.live_rules import LiveRules
from investigation.modules.detections.process_tree import ProcessTree

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
_n = [0]


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))


def ev(artifact, **fields):
    return Event(timestamp=T0, timestamp_desc="x", artifact=artifact, source_file="volatile/x.csv",
                 message=artifact, fields=fields)


def ids(tmp_path, events, module=LiveRules):
    _n[0] += 1
    store = EventStore(tmp_path / f"t{_n[0]}.db")
    store.add_many(events)
    return {f.rule_id for f in module().detect(store, Context())}


def test_live_rules_each_rule(tmp_path):
    bad = ev("live_process", exe="C:\\Users\\x\\AppData\\Local\\Temp\\e.exe", signed="unsigned")
    assert ids(tmp_path, [bad]) == {"INV-LIVE-001"}
    assert ids(tmp_path, [ev("live_process", exe=bad.fields["exe"], signed="signed")]) == set()
    assert ids(tmp_path, [ev("live_process", exe="C:\\Windows\\a.exe", signed="")]) == set()

    net = ev("live_network", remote_addr="8.8.8.8", process="PowerShell.exe")
    assert ids(tmp_path, [net]) == {"INV-LIVE-002"}
    assert ids(tmp_path, [ev("live_network", remote_addr="10.0.0.5", process="powershell.exe")]) == set()
    assert ids(tmp_path, [ev("live_network", remote_addr="8.8.8.8", process="chrome.exe")]) == set()
    assert ids(tmp_path, [ev("live_network", remote_addr="not-an-ip", process="mshta.exe")]) == set()

    assert ids(tmp_path, [ev("live_wmi_subscription", kind="CommandLineEventConsumer")]) == {"INV-LIVE-003"}
    assert ids(tmp_path, [ev("live_wmi_subscription", kind="__EventFilter")]) == set()

    assert ids(tmp_path, [ev("live_defender", key="DisableRealtimeMonitoring", value="true")]) == {"INV-LIVE-004"}
    assert ids(tmp_path, [ev("live_defender", key="ExclusionPath", value="C:\\x")]) == {"INV-LIVE-004"}
    assert ids(tmp_path, [ev("live_defender", key="ExclusionPath", value="")]) == set()
    assert ids(tmp_path, [ev("live_defender", key="DisableRealtimeMonitoring", value="false")]) == set()


def test_process_tree_reads_live_processes(tmp_path):
    def p(pid, ppid, name):
        return ev("live_process", PID=pid, PPID=ppid, ImageFileName=name, ExitTime="")
    events = [p(1000, 0, "explorer.exe"), p(700, 1000, "lsass.exe")]
    assert "INV-PROC-001" in ids(tmp_path, events, ProcessTree)


@pytest.mark.parametrize("signed,fires", [("unsigned", True), ("error", True), ("", False),
                                          ("remote-skipped", False), ("signed", False)])
def test_rule_001_signed_values(tmp_path, signed, fires):
    e = ev("live_process", exe="C:\\Users\\x\\AppData\\a.exe", signed=signed)
    assert (ids(tmp_path, [e]) == {"INV-LIVE-001"}) is fires


def test_rule_002_ipv4_mapped_ipv6(tmp_path):
    assert ids(tmp_path, [ev("live_network", remote_addr="::ffff:8.8.8.8", process="mshta.exe")]) == {"INV-LIVE-002"}
    assert ids(tmp_path, [ev("live_network", remote_addr="::ffff:10.0.0.5", process="mshta.exe")]) == set()


def test_process_tree_artifacts_evaluated_separately(tmp_path):
    def p(art, pid, ppid, name):
        return ev(art, PID=pid, PPID=ppid, ImageFileName=name, ExitTime="")
    both = [p("memory_process", 500, 400, "wininit.exe"), p("memory_process", 700, 500, "lsass.exe"),
            p("live_process", 5, 4, "wininit.exe"), p("live_process", 7, 5, "lsass.exe")]
    assert "INV-PROC-002" not in ids(tmp_path, both, ProcessTree)
    live2 = both[2:] + [p("live_process", 8, 5, "lsass.exe")]
    assert "INV-PROC-002" in ids(tmp_path, live2, ProcessTree)
