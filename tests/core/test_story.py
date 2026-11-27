from datetime import datetime, timedelta, timezone

from investigation.core.models import Event, EvidenceType, Finding, Severity
from investigation.core.store import EventStore
from investigation.core.story import SECTIONS, build_story, candidate_names, notes_for

T0 = datetime(2024, 5, 1, tzinfo=timezone.utc)


def ev(i, artifact, et, message="", user=None, desc="t", **fields):
    return Event(timestamp=T0 + timedelta(minutes=i), timestamp_desc=desc, artifact=artifact, source_file="s",
                 message=message, user=user, fields=fields, evidence_type=et)


def finding(*events, sev=Severity.HIGH):
    return Finding("R", "t", sev, "d", ("T1",), list(events))


def test_candidate_names_filters_system_and_short():
    f1 = finding(ev(0, "evtx", EvidenceType.EXECUTION, message=r"cmd.exe /c C:\Users\Public\evil_tool.exe a.exe",
                    CommandLine=r"C:\Windows\System32\cmd.exe /c C:\Users\Public\evil_tool.exe"))
    f2 = finding(ev(0, "bam", EvidenceType.EXECUTION, path=r"\Device\HarddiskVolume3\Temp\Dropper.EXE"),
                 sev=Severity.CRITICAL)
    assert candidate_names([f1, f2]) == ["dropper.exe", "evil_tool.exe"]


def test_build_story_sections(tmp_path):
    store = EventStore(tmp_path / "db")
    store.add_many([
        ev(0, "browser", EvidenceType.NETWORK, "chrome download: http://x/evil_tool.exe",
           url="http://x/evil_tool.exe", path=r"C:\Users\bob\Downloads\evil_tool.exe"),
        ev(1, "prefetch", EvidenceType.EXECUTION, "EVIL_TOOL.EXE executed", filename="EVIL_TOOL.EXE",
           linkedfiles=r"\VOLUME{1}\USERS\BOB\SECRET.DOCX"),
        ev(2, "bam", EvidenceType.EXECUTION, r"C:\Users\bob\Downloads\evil_tool.exe", user="bob"),
        ev(3, "runkeys", EvidenceType.PERSISTENCE, r"upd = C:\Users\bob\Downloads\evil_tool.exe"),
        ev(4, "amcache", EvidenceType.EXISTENCE, r"c:\users\bob\downloads\evil_tool.exe",
           path=r"c:\users\bob\downloads\evil_tool.exe", digest_sha1="abc"),
        ev(5, "lnk", EvidenceType.FILE_ACCESS, r"report.lnk -> C:\x\report.docx"),
    ])
    s = build_story(store, "evil_tool.exe")
    assert list(s.sections) == SECTIONS
    assert [e.artifact for e in s.sections["Where did it come from?"]] == ["browser"]
    assert {e.artifact for e in s.sections["When did it run?"]} == {"prefetch", "bam"}
    assert [e.user for e in s.sections["Who ran it?"]] == ["bob"]
    assert [e.artifact for e in s.sections["Did it persist?"]] == ["runkeys"]
    assert [e.artifact for e in s.sections["What did it touch?"]] == ["prefetch"]
    assert s.hashes == {"sha1": "abc"}
    d = s.to_dict()
    assert d["name"] == "evil_tool.exe" and d["sections"]["Hashes"] == []


def test_story_limit(tmp_path):
    store = EventStore(tmp_path / "db")
    store.add_many(ev(i, "bam", EvidenceType.EXECUTION, "loop.exe") for i in range(300))
    s = build_story(store, "loop.exe")
    assert sum(len(v) for v in s.sections.values()) <= 200


def test_search_escapes_like(tmp_path):
    store = EventStore(tmp_path / "db")
    store.add_many([ev(0, "bam", EvidenceType.EXECUTION, "100%_done.exe"),
                    ev(1, "bam", EvidenceType.EXECUTION, "100XYdone.exe")])
    assert [e.message for e in store.search("100%_done.exe")] == ["100%_done.exe"]


def test_notes_for():
    notes = notes_for(["shimcache", "evtx", "prefetch"])
    assert "Shimcache does not prove execution" in notes["shimcache"]
    assert "Server" in notes["prefetch"]
    assert "audit-policy" in notes["evtx"]
    assert "lnk" not in notes_for(["lnk"])


def test_story_matches_whole_names_and_own_hashes(tmp_path):
    store = EventStore(tmp_path / "db")
    store.add_many([
        ev(0, "amcache", EvidenceType.EXISTENCE, r"c:\x\notevil.exe", path=r"c:\x\notevil.exe", digest_sha1="WRONG"),
        ev(1, "amcache", EvidenceType.EXISTENCE, r"c:\x\evil.exe", path=r"c:\x\evil.exe", digest_sha1="RIGHT"),
        ev(2, "bam", EvidenceType.EXECUTION, r"c:\x\myevil.exe.bak"),
    ])
    s = build_story(store, "evil.exe")
    assert s.hashes == {"sha1": "RIGHT"}
    assert [e.message for e in s.all_events] == [r"c:\x\evil.exe"]


def test_story_keeps_late_persistence_beyond_limit(tmp_path):
    store = EventStore(tmp_path / "db")
    store.add_many([ev(i, "srum", EvidenceType.EXECUTION, r"c:\x\busy.exe") for i in range(400)])
    store.add_many([ev(1000, "runkeys", EvidenceType.PERSISTENCE, r"upd = c:\x\busy.exe")])
    s = build_story(store, "busy.exe")
    assert len(s.sections["Did it persist?"]) == 1
    assert s.truncated["When did it run?"] is True


def test_story_non_ascii_name(tmp_path):
    store = EventStore(tmp_path / "db")
    store.add_many([ev(0, "bam", EvidenceType.EXECUTION, r"C:\x\Ärger.exe")])
    assert len(build_story(store, "ärger.exe").sections["When did it run?"]) == 1
