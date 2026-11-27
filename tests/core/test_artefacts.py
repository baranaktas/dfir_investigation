import json
import zipfile
from datetime import datetime, timedelta, timezone

from investigation.core.artefacts import TAG, Collector, collector_from_manifest, is_artefact, load_collector, mark
from investigation.core.models import Event, EvidenceType
from investigation.core.store import EventStore

START = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
END = START + timedelta(minutes=10)
SHA = "ab" * 32
COLLECTOR = Collector("investigation.exe", SHA, START, END)


def ev(minutes=1, artifact="evtx", fields=None, message="m", **kw):
    return Event(timestamp=START + timedelta(minutes=minutes), timestamp_desc="d", artifact=artifact,
                 source_file="f", message=message, fields=fields or {}, evidence_type=EvidenceType.EXECUTION, **kw)


def test_pmem_service_install_inside_window_is_artefact():
    e = ev(fields={"Channel": "System", "EventID": 7045, "ServiceName": "pmem",
                   "ImagePath": r"C:\Windows\Temp\pmeA1B2.tmp"})
    assert is_artefact(e, COLLECTOR)
    assert is_artefact(ev(fields={"Channel": "Security", "EventID": 4697, "ServiceName": "pmem"}), COLLECTOR)


def test_pmem_temp_file_is_artefact():
    assert is_artefact(ev(artifact="mft", message=r"created C:\Windows\Temp\pme9F.tmp"), COLLECTOR)


def test_collector_executable_artifacts_match_by_name():
    cases = [
        ev(artifact="prefetch", fields={"filename": "INVESTIGATION.EXE"}),
        ev(artifact="bam", fields={"path": r"\Device\HarddiskVolume3\Tools\investigation.exe"}),
        ev(artifact="amcache", fields={"path": r"C:\Tools\Investigation.exe"}),
        ev(fields={"Channel": "Security", "EventID": 4688, "NewProcessName": r"C:\Tools\investigation.exe"}),
        ev(fields={"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1,
                   "Image": r"C:\Tools\investigation.exe"}),
        ev(fields={"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 9,
                   "Image": r"C:\Tools\investigation.exe", "Device": r"\Device\HarddiskVolume3"}),
        ev(fields={"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Image": r"C:\Windows\System32\consent.exe",
                   "CommandLine": r"consent.exe 1234 C:\Tools\investigation.exe"}),
    ]
    assert all(is_artefact(e, COLLECTOR) for e in cases)


def test_matching_hash_stays_artefact_and_different_hash_does_not():
    base = {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1, "Image": r"C:\Tools\investigation.exe"}
    assert is_artefact(ev(fields={**base, "Hashes": f"SHA1=AA,SHA256={SHA.upper()},MD5=BB"}), COLLECTOR)
    assert not is_artefact(ev(fields={**base, "Hashes": "SHA256=" + "cd" * 32}), COLLECTOR)
    assert not is_artefact(ev(artifact="amcache", fields={"path": r"C:\x\investigation.exe", "digest_sha256": "cd" * 32}),
                           COLLECTOR)


def test_outside_window_is_a_normal_event():
    service = {"Channel": "System", "EventID": 7045, "ServiceName": "pmem"}
    assert not is_artefact(ev(minutes=-3, fields=service), COLLECTOR)
    assert not is_artefact(ev(minutes=13, fields=service), COLLECTOR)
    assert is_artefact(ev(minutes=-1.5, fields=service), COLLECTOR)
    assert is_artefact(ev(minutes=11.5, fields=service), COLLECTOR)


def test_other_service_and_other_exe_are_normal():
    assert not is_artefact(ev(fields={"Channel": "System", "EventID": 7045, "ServiceName": "evilsvc"}), COLLECTOR)
    assert not is_artefact(ev(fields={"Channel": "Security", "EventID": 4688, "NewProcessName": r"C:\x\other.exe"}),
                           COLLECTOR)


def test_no_collector_means_nothing_is_an_artefact():
    assert not is_artefact(ev(fields={"Channel": "System", "EventID": 7045, "ServiceName": "pmem"}), None)


def test_vss_provider_events_in_window():
    assert is_artefact(ev(fields={"Channel": "Application", "EventID": 8194, "Provider_Name": "VSS"}), COLLECTOR)


def manifest(**extra):
    return {"format_version": 1, "started_utc": START.isoformat(), "finished_utc": END.isoformat(), **extra}


def test_collector_from_manifest():
    c = collector_from_manifest(manifest(collector={"name": "investigation.exe", "sha256": SHA.upper()}))
    assert c == COLLECTOR
    assert collector_from_manifest(manifest()).name == ""
    assert collector_from_manifest({"format_version": 1}) is None
    assert collector_from_manifest(None) is None


def test_load_collector_from_folder_and_zip(tmp_path):
    folder = tmp_path / "pkg"
    folder.mkdir()
    data = manifest(collector={"name": "investigation.exe", "sha256": SHA})
    (folder / "manifest.json").write_text(json.dumps(data))
    assert load_collector(folder) == COLLECTOR
    z = tmp_path / "pkg.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("pkg/manifest.json", json.dumps(data))
    assert load_collector(z) == COLLECTOR
    assert load_collector(tmp_path) is None


def test_name_less_manifest_still_marks_the_pmem_service():
    c = collector_from_manifest(manifest())
    assert is_artefact(ev(fields={"Channel": "System", "EventID": 7045, "ServiceName": "pmem"}), c)
    assert not is_artefact(ev(artifact="bam", fields={"path": r"C:\x\investigation.exe"}), c)


def test_store_hides_artefacts_unless_asked(tmp_path):
    store = EventStore(tmp_path / "db")
    store.add_many(mark([ev(fields={"Channel": "System", "EventID": 7045, "ServiceName": "pmem"}),
                         ev(2, fields={"Channel": "System", "EventID": 7045, "ServiceName": "other"})], COLLECTOR))
    assert store.count() == 2
    assert [e.fields["ServiceName"] for e in store.iter_events(artifact="evtx")] == ["other"]
    assert len(list(store.iter_events(include_artefacts=True))) == 2
    got = list(store.iter_artefacts())
    assert len(got) == 1 and TAG in got[0].tags


def test_pipeline_reports_artefacts_without_findings(tmp_path):
    from investigation.core.pipeline import analyze

    pkg = tmp_path / "pkg"
    (pkg / "files").mkdir(parents=True)
    out = tmp_path / "out"
    manifest_data = {"format_version": 1, "started_utc": START.isoformat(), "finished_utc": END.isoformat(),
                     "collector": {"name": "investigation.exe", "sha256": SHA}, "files": []}
    (pkg / "manifest.json").write_text(json.dumps(manifest_data))
    result = analyze(pkg, out, profile="triage")
    assert result.collector == COLLECTOR
    assert (out / "report.html").is_file()
    assert "Collection artefacts (0)" in (out / "report.html").read_text(encoding="utf-8")
    assert json.loads((out / "findings.json").read_text())["collection_artefacts"] == 0
