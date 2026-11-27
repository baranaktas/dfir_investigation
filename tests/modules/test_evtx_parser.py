import json
import os
import shutil
from pathlib import Path

import pytest

from investigation.core.models import EvidenceType
from investigation.core.requirements import Context
from investigation.modules.parsers.evtx import EvtxParser
from investigation.modules.sources.directory import DirectoryEvidence

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "evtx"


def parse(root):
    errors = []
    events = list(EvtxParser().parse(DirectoryEvidence(root), Context(), lambda m, msg: errors.append((m, msg))))
    return events, errors


@pytest.fixture(scope="module")
def parsed():
    return parse(FIXTURES)


def by_id(events, eid):
    return [e for e in events if e.fields.get("EventID") == eid]


def test_parses_1102(parsed):
    events, errors = parsed
    assert errors == []
    [e] = by_id(events, 1102)
    assert e.host == "PC01.example.corp"
    assert e.fields["SubjectUserName"] == "user01"
    assert e.user == "user01"
    assert e.fields["Channel"] == "Security"
    assert e.artifact == "evtx"
    assert e.source_file == "1102_security_log_cleared.evtx"
    assert e.timestamp.tzinfo is not None
    assert not any("xmlns" in k for k in e.fields)
    assert "Provider_Guid" not in e.fields


def test_parses_7045_fields(parsed):
    events, _ = parsed
    svc = by_id(events, 7045)
    assert len(svc) == 3
    spool = [e for e in svc if e.fields["ServiceName"] == "spoolfool"]
    assert spool and spool[0].fields["ImagePath"] == "cmd.exe"
    assert "ServiceName=spoolfool" in spool[0].message
    assert spool[0].message.startswith("System 7045:")


def test_4625_logon_fields(parsed):
    events, _ = parsed
    [e] = by_id(events, 4625)
    assert e.fields["LogonType"] == 2
    assert e.fields["TargetUserName"] == "IEUser"
    assert e.user == "IEUser"


def test_evidence_types(parsed):
    events, _ = parsed
    assert by_id(events, 1102)[0].evidence_type is EvidenceType.OTHER
    assert by_id(events, 7045)[0].evidence_type is EvidenceType.PERSISTENCE
    assert by_id(events, 4625)[0].evidence_type is EvidenceType.AUTHENTICATION
    sysmon1 = [e for e in by_id(events, 1) if "Sysmon" in e.fields["Channel"]]
    assert sysmon1 and all(e.evidence_type is EvidenceType.EXECUTION for e in sysmon1)


def test_all_events_json_safe(parsed):
    events, _ = parsed
    assert len(events) > 10
    for e in events:
        json.dumps(e.to_dict())


def test_corrupt_file_reported_and_others_continue(tmp_path):
    for f in FIXTURES.glob("*.evtx"):
        shutil.copy(f, tmp_path / f.name)
    (tmp_path / "broken.evtx").write_bytes(os.urandom(4096))
    (tmp_path / "truncated.evtx").write_bytes((FIXTURES / "7045_remote_service.evtx").read_bytes()[:5000])
    events, errors = parse(tmp_path)
    assert any("broken.evtx" in msg for _, msg in errors)
    assert all(m == "evtx" for m, _ in errors)
    assert by_id(events, 1102)


class RecordingSource(DirectoryEvidence):
    is_system = True

    def __init__(self, root):
        super().__init__(root)
        self.patterns = []

    def glob(self, pattern):
        self.patterns.append(pattern)
        return iter(())


def test_evtx_patterns_anchored_on_system_source(tmp_path):
    src = RecordingSource(tmp_path)
    list(EvtxParser().parse(src, Context(), lambda m, s: None))
    assert src.patterns == ["windows/system32/winevt/logs/*.evtx"]


def test_defender_detection_message_has_threat_and_path(tmp_path):
    src = Path(__file__).resolve().parent.parent / "fixtures" / "windows" / "Microsoft-Windows-Windows Defender%4Operational.evtx"
    shutil.copy(src, tmp_path / "defender.evtx")
    events, errors = parse(tmp_path)
    det = [e for e in events if e.fields.get("EventID") == 1116]
    assert det and "ThreatName=" in det[0].message and "Path=" in det[0].message


def test_zero_filled_evtx_summarised_once(tmp_path):
    logs = tmp_path / "Windows" / "System32" / "winevt" / "Logs"
    logs.mkdir(parents=True)
    for i in range(3):
        (logs / f"z{i}.evtx").write_bytes(b"\0" * 69632)
    (logs / "junk.evtx").write_bytes(b"NOTEVTX!" + b"\0" * 5000)
    errors = []
    list(EvtxParser().parse(DirectoryEvidence(tmp_path), Context(), lambda m, msg: errors.append(msg)))
    assert sum("bad header" in e for e in errors) == 1 and any("junk.evtx" in e for e in errors)
    zero = [e for e in errors if "zero-filled" in e]
    assert len(zero) == 1 and zero[0].startswith("3 EVTX file(s)")
