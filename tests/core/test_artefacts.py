import json
import zipfile
from datetime import datetime, timedelta, timezone

from investigation.core.artefacts import (TAG, Collector, _winpmem_name_and_hash, classify, collector_from_manifest, is_artefact,
                                          load_collector, mark)
from investigation.core.models import Event, EvidenceType
from investigation.core.store import EventStore

START = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)
END = START + timedelta(minutes=10)
SHA = "ab" * 32
COLLECTOR = Collector("investigation.exe", SHA, START, END)


def ev(minutes=1, artifact="evtx", fields=None, message="m", **kw):
    return Event(timestamp=START + timedelta(minutes=minutes), timestamp_desc="d", artifact=artifact,
                 source_file="f", message=message, fields=fields or {}, evidence_type=EvidenceType.EXECUTION, **kw)


PMEM = {"Channel": "System", "EventID": 7045, "ServiceName": "pmem", "ImagePath": r"C:\Windows\Temp\pmeA1B2.tmp"}
SYSMON = "Microsoft-Windows-Sysmon/Operational"


def test_pmem_service_install_with_exact_image_path_is_artefact():
    assert classify(ev(fields=PMEM), COLLECTOR) == "artefact"
    assert classify(ev(fields={**PMEM, "EventID": 4697}), COLLECTOR) == "artefact"


def test_pmem_lookalikes_are_not_suppressed():
    bad_paths = [r"C:\Users\x\evil.exe", r"C:\Windows\Temp\pme1.tmp & calc", r"C:\Windows\Temp\pmeZZ.tmp",
                 r"C:\Windows\Temp\pme1.tmp.exe"]
    for path in bad_paths:
        e = ev(fields={**PMEM, "ImagePath": path})
        assert not is_artefact(e, COLLECTOR)
        assert classify(e, COLLECTOR) == "possible"
    assert not is_artefact(ev(fields={**PMEM, "ServiceName": "pmem2"}), COLLECTOR)
    assert not is_artefact(ev(fields={**PMEM, "ServiceName": "evil", "Note": r"Temp\pme1.tmp"}), COLLECTOR)


def test_flattened_text_is_never_matched():
    assert not is_artefact(ev(artifact="mft", message=r"created C:\Windows\Temp\pme9F.tmp"), COLLECTOR)


def test_collector_events_need_a_matching_hash():
    base = {"Channel": SYSMON, "EventID": 1, "Image": r"C:\Tools\investigation.exe"}
    assert is_artefact(ev(fields={**base, "Hashes": f"SHA1=AA,SHA256={SHA.upper()},MD5=BB"}), COLLECTOR)
    wp_hash = _winpmem_name_and_hash()[1]
    assert is_artefact(ev(fields={"Channel": SYSMON, "EventID": 1, "Image": r"C:\Windows\Temp\winpmem_mini_x64_rc2.exe",
                                  "Hashes": f"SHA256={wp_hash}"}), COLLECTOR)


def test_lookalike_collector_with_different_hash_is_reported():
    base = {"Channel": SYSMON, "EventID": 1, "Image": r"C:\Users\x\investigation.exe"}
    e = ev(fields={**base, "Hashes": "SHA256=" + "cd" * 32})
    assert classify(e, COLLECTOR) is None
    e = ev(artifact="amcache", fields={"path": r"C:\x\investigation.exe", "digest_sha256": "cd" * 32})
    assert classify(e, COLLECTOR) is None


def test_name_match_without_hash_is_kept_visible_with_a_note():
    cases = [
        ev(artifact="prefetch", fields={"filename": "INVESTIGATION.EXE"}),
        ev(artifact="bam", fields={"path": r"\Device\HarddiskVolume3\Tools\investigation.exe"}),
        ev(fields={"Channel": "Security", "EventID": 4688, "NewProcessName": r"C:\Tools\investigation.exe"}),
        ev(fields={"Channel": SYSMON, "EventID": 1, "Image": r"C:\Tools\investigation.exe"}),
    ]
    assert [classify(e, COLLECTOR) for e in cases] == ["possible"] * 4
    assert not any(is_artefact(e, COLLECTOR) for e in cases)


def test_name_prefix_alone_is_not_enough():
    e = ev(fields={"Channel": SYSMON, "EventID": 1, "Image": r"C:\x\winpmem_evil.exe"})
    assert classify(e, COLLECTOR) is None
    e = ev(fields={"Channel": SYSMON, "EventID": 1, "Image": r"C:\x\investigation.exe.bak"})
    assert classify(e, COLLECTOR) is None


def test_command_line_naming_the_collector_is_reported():
    e = ev(fields={"Channel": "Security", "EventID": 4688, "NewProcessName": r"C:\Windows\System32\cmd.exe",
                   "CommandLine": r"cmd.exe /c C:\Tools\investigation.exe && evil"})
    assert classify(e, COLLECTOR) is None
    e = ev(fields={"Channel": SYSMON, "EventID": 1, "Image": r"C:\Windows\System32\consent.exe",
                   "CommandLine": r"consent.exe 1234 C:\Tools\investigation.exe"})
    assert classify(e, COLLECTOR) is None


def test_outside_window_is_a_normal_event():
    assert classify(ev(minutes=-3, fields=PMEM), COLLECTOR) is None
    assert classify(ev(minutes=13, fields=PMEM), COLLECTOR) is None
    assert is_artefact(ev(minutes=-1.5, fields=PMEM), COLLECTOR)
    assert is_artefact(ev(minutes=11.5, fields=PMEM), COLLECTOR)


def test_other_service_and_other_exe_are_normal():
    assert classify(ev(fields={"Channel": "System", "EventID": 7045, "ServiceName": "evilsvc"}), COLLECTOR) is None
    assert classify(ev(fields={"Channel": "Security", "EventID": 4688, "NewProcessName": r"C:\x\other.exe"}),
                    COLLECTOR) is None


def test_no_collector_means_nothing_is_an_artefact():
    assert classify(ev(fields=PMEM), None) is None


def test_shadow_copy_events_are_never_suppressed():
    deletion = ev(fields={"Channel": "Application", "EventID": 8194, "Provider_Name": "VSS"})
    resize = ev(fields={"Channel": "System", "EventID": 524, "Provider_Name": "Microsoft-Windows-Ntfs"})
    cmd = ev(fields={"Channel": "Security", "EventID": 4688, "NewProcessName": r"C:\Windows\System32\vssadmin.exe",
                     "CommandLine": "vssadmin delete shadows /all"})
    for e in (deletion, resize, cmd):
        assert classify(e, COLLECTOR) is None


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
    assert is_artefact(ev(fields=PMEM), c)
    assert classify(ev(artifact="bam", fields={"path": r"C:\x\investigation.exe"}), c) is None


def test_store_keeps_artefacts_visible_to_detections(tmp_path):
    store = EventStore(tmp_path / "db")
    store.add_many(mark([ev(fields=PMEM),
                         ev(2, fields={"Channel": "System", "EventID": 7045, "ServiceName": "other"})], COLLECTOR))
    assert store.count() == 2
    assert len(list(store.iter_events(artifact="evtx"))) == 2
    got = list(store.iter_artefacts())
    assert len(got) == 1 and TAG in got[0].tags


def test_finding_of_only_verified_artefacts_is_moved_and_mixed_one_stays():
    from investigation.core.artefacts import split_findings
    from investigation.core.models import Finding, Severity

    art = next(mark([ev(fields=PMEM)], COLLECTOR))
    normal = ev(2, fields={"Channel": "System", "EventID": 7045, "ServiceName": "other"})
    only = Finding("R1", "t", Severity.HIGH, "d", (), [art])
    mixed = Finding("R2", "t", Severity.HIGH, "d", (), [art, normal])
    kept, moved = split_findings([only, mixed])
    assert [f.rule_id for f in kept] == ["R2"] and [f.rule_id for f in moved] == ["R1"]


def test_implausible_windows_disable_suppression():
    notes = []
    backwards = manifest(started_utc=END.isoformat(), finished_utc=START.isoformat())
    assert collector_from_manifest(backwards, notes.append) is None
    too_long = manifest(finished_utc=(START + timedelta(hours=25)).isoformat())
    assert collector_from_manifest(too_long, notes.append) is None
    assert len(notes) == 2


def test_collector_name_needs_a_manifest_hash():
    c = collector_from_manifest(manifest(collector={"name": "investigation.exe", "sha256": ""}))
    e = ev(fields={"Channel": SYSMON, "EventID": 1, "Image": r"C:\x\investigation.exe", "Hashes": "SHA256=" + "cd" * 32})
    assert classify(e, c) is None
    e = ev(fields={"Channel": SYSMON, "EventID": 1, "Image": r"C:\x\investigation.exe"})
    assert classify(e, c) is None


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
