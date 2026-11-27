import json
from datetime import datetime, timezone

import pytest

from investigation.core.models import Event, EvidenceType, Finding, Severity


class FakeSid:
    def __str__(self) -> str:
        return "S-1-5-18"


def _event(**kw):
    base = dict(
        timestamp=datetime(2019, 3, 19, 23, 35, 7, 524200, tzinfo=timezone.utc),
        timestamp_desc="Event Logged",
        artifact="evtx",
        source_file="Security.evtx",
        message="msg",
    )
    base.update(kw)
    return Event(**base)


def test_event_to_dict_is_json_safe():
    e = _event(fields={"sid": FakeSid(), "raw": b"\x01\x02", "n": 4, "ok": True, "none": None})
    d = e.to_dict()
    json.dumps(d)
    assert d["timestamp"] == "2019-03-19T23:35:07.524200+00:00"
    assert d["fields"]["raw"] == "0102"
    assert d["fields"]["sid"] == "S-1-5-18"
    assert d["fields"]["n"] == 4
    assert d["evidence_type"] == "other"


def test_event_rejects_naive_timestamp():
    with pytest.raises(ValueError):
        _event(timestamp=datetime(2020, 1, 1))


def test_event_evidence_type():
    assert _event(evidence_type=EvidenceType.EXECUTION).to_dict()["evidence_type"] == "execution"


def test_severity_parse_and_order():
    assert Severity.parse("High") == Severity.HIGH
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
    assert str(Severity.HIGH) == "high"
    with pytest.raises(ValueError):
        Severity.parse("bogus")


def test_finding_to_dict():
    f = Finding("R1", "t", Severity.HIGH, "d", ("T1070.001",), [_event()])
    d = f.to_dict()
    json.dumps(d)
    assert d["severity"] == "high"
    assert d["mitre"] == ["T1070.001"]
    assert len(d["events"]) == 1
