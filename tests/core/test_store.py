from datetime import datetime, timedelta, timezone

from investigation.core.models import Event, EvidenceType
from investigation.core.store import EventStore

T0 = datetime(2020, 1, 1, tzinfo=timezone.utc)


class Sid:
    def __str__(self):
        return "S-1-5-18"


def ev(i, artifact="evtx", **fields):
    return Event(
        timestamp=T0 + timedelta(seconds=i), timestamp_desc="Event Logged", artifact=artifact,
        source_file="a.evtx", message=f"m{i}", host="H", user="u", fields=fields,
        tags=("t",), evidence_type=EvidenceType.AUTHENTICATION,
    )


def test_store_roundtrip_sorted(tmp_path):
    s = EventStore(tmp_path / "db.sqlite")
    events = [ev(3, EventID=4625, sid=Sid()), ev(1, EventID=4624), ev(2, EventID=4625)]
    assert s.add_many(events) == 3
    out = list(s.iter_events())
    assert [e.message for e in out] == ["m1", "m2", "m3"]
    assert out[0] == ev(1, EventID=4624)
    assert out[2].fields["sid"] == "S-1-5-18"
    assert out[0].evidence_type is EvidenceType.AUTHENTICATION
    assert out[0].timestamp.tzinfo is not None
    assert s.count() == 3


def test_store_field_equals(tmp_path):
    s = EventStore(tmp_path / "db.sqlite")
    s.add_many([ev(1, EventID=4624), ev(2, EventID=4625), ev(3, EventID=4625, LogonType=10)])
    assert [e.message for e in s.iter_events(field_equals={"EventID": 4625})] == ["m2", "m3"]
    assert [e.message for e in s.iter_events(field_equals={"EventID": 4625, "LogonType": 10})] == ["m3"]


def test_artifact_counts(tmp_path):
    s = EventStore(tmp_path / "db.sqlite")
    s.add_many([ev(1), ev(2), ev(3, artifact="prefetch")])
    assert s.artifact_counts() == {"evtx": 2, "prefetch": 1}
    assert [e.message for e in s.iter_events(artifact="prefetch")] == ["m3"]


def test_add_many_batches_generator(tmp_path):
    s = EventStore(tmp_path / "db.sqlite")
    assert s.add_many(ev(i) for i in range(2500)) == 2500
    assert s.count() == 2500
