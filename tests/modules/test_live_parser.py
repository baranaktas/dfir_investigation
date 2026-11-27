from datetime import datetime, timezone
from types import SimpleNamespace

from investigation.core.models import EvidenceType
from investigation.core.requirements import Context
from investigation.modules.collectors.base import write_csv
from investigation.modules.parsers.live import LIVE_SPECS, LiveParser

STARTED = "2026-11-26T10:00:00+00:00"


def _pkg(tmp_path, manifest=None):
    (tmp_path / "volatile").mkdir()
    return SimpleNamespace(package_root=tmp_path, manifest={"started_utc": STARTED} if manifest is None else manifest)


def _parse(src):
    errs = []
    events = list(LiveParser().parse(src, Context(), lambda m, t: errs.append((m, t))))
    return events, errs


def test_live_parser_events_and_times(tmp_path):
    src = _pkg(tmp_path)
    write_csv(tmp_path / "volatile/processes.csv",
              ("pid", "ppid", "name", "exe", "cmdline", "user", "create_time_utc", "sha256", "signed"),
              [{"pid": 7, "ppid": 3, "name": "a.exe", "exe": "C:\\a.exe", "cmdline": "a.exe -x {y}",
                "create_time_utc": datetime(2026, 11, 26, 9, 0, tzinfo=timezone.utc), "signed": "signed"}])
    write_csv(tmp_path / "volatile/network.csv",
              ("proto", "local_addr", "local_port", "remote_addr", "remote_port", "state", "pid", "process"),
              [{"proto": "tcp", "local_addr": "1.1.1.1", "local_port": 5, "remote_addr": "8.8.8.8",
                "remote_port": 443, "state": "ESTABLISHED", "pid": 7, "process": "a.exe"}])
    events, errs = _parse(src)
    assert errs == []
    p = next(e for e in events if e.artifact == "live_process")
    assert p.timestamp_desc == "Process Started" and p.timestamp.hour == 9
    assert p.message == "a.exe pid=7 ppid=3: a.exe -x {y}"
    assert p.source_file == "volatile/processes.csv" and p.evidence_type == EvidenceType.EXECUTION
    assert p.fields["PID"] == 7 and p.fields["PPID"] == 3 and p.fields["ImageFileName"] == "a.exe"
    assert p.fields["ExitTime"] == ""
    n = next(e for e in events if e.artifact == "live_network")
    assert n.timestamp_desc == "Observed at Collection"
    assert n.timestamp == datetime(2026, 11, 26, 10, 0, tzinfo=timezone.utc)
    assert n.message == "tcp 1.1.1.1:5 -> 8.8.8.8:443 ESTABLISHED (a.exe)"
    assert "system_info" not in LIVE_SPECS


def test_live_parser_restores_neutralized_cells(tmp_path):
    src = _pkg(tmp_path)
    write_csv(tmp_path / "volatile/processes.csv", ("pid", "ppid", "name", "cmdline"),
              [{"pid": 1, "ppid": 0, "name": "x.exe", "cmdline": "=cmd /c calc"}])
    events, _ = _parse(src)
    assert "=cmd /c calc" in events[0].message and "'=cmd" not in events[0].message


def test_live_parser_bad_rows_and_manifest(tmp_path):
    src = _pkg(tmp_path, manifest={})
    write_csv(tmp_path / "volatile/processes.csv", ("pid", "ppid", "name", "create_time_utc"),
              [{"pid": "abc", "ppid": "", "name": "bad", "create_time_utc": "garbage"}])
    write_csv(tmp_path / "volatile/pipes.csv", ("name",), [{"name": "\\\\.\\pipe\\x"}])
    events, errs = _parse(src)
    assert {e.artifact for e in events} >= {"live_pipe"}
    assert all(e.timestamp.tzinfo for e in events)
    (bad,) = [e for e in events if e.artifact == "live_process"]
    assert bad.fields["PID"] is None and bad.timestamp_desc == "Observed at Collection"
    assert errs == []


def test_live_parser_skips_symlinked_csv(tmp_path):
    src = _pkg(tmp_path)
    outside = tmp_path.parent / (tmp_path.name + "_out.csv")
    write_csv(outside, ("name",), [{"name": "p"}])
    (tmp_path / "volatile/pipes.csv").symlink_to(outside)
    events, _ = _parse(src)
    assert events == []


def test_live_parser_ignores_non_package_source():
    assert list(LiveParser().parse(SimpleNamespace(), Context(), lambda m, t: None)) == []


def test_live_parser_short_rows_and_time_formats(tmp_path):
    src = _pkg(tmp_path)
    (tmp_path / "volatile/hotfixes.csv").write_text(
        "id,description,installed_on,installed_by\nKB1,fix,11/5/2026 12:00:00 AM\nKB2,fix,20261105,x,extra\n"
        "KB3,fix,99999999999999\n", encoding="utf-8")
    events, errs = _parse(src)
    assert len(events) == 3 and errs == []
    assert events[0].timestamp == datetime(2026, 11, 5, tzinfo=timezone.utc)
    assert events[1].timestamp == datetime(2026, 11, 5, tzinfo=timezone.utc)
    assert events[2].timestamp_desc == "Observed at Collection"


def test_live_parser_row_error_cap_summary(tmp_path, monkeypatch):
    src = _pkg(tmp_path)
    write_csv(tmp_path / "volatile/pipes.csv", ("name",), [{"name": str(i)} for i in range(9)])

    def boom(*a, **k):
        raise ValueError("bad")

    monkeypatch.setattr(LiveParser, "_event", staticmethod(boom))
    events, errs = _parse(src)
    assert events == [] and len(errs) == 6 and "4 more rows failed in pipes.csv" in errs[-1][1]
