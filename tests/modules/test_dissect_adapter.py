import json
from datetime import datetime, timezone

import pytest
from flow.record import RecordDescriptor

from investigation.core.models import EvidenceType
from investigation.core.registry import ModuleRegistry
from investigation.core.requirements import Context
from investigation.modules.parsers.dissect_adapter import (
    ArtifactSpec,
    load_catalog,
    record_fields,
    record_to_events,
)
from investigation.modules.sources.directory import DirectoryEvidence
from investigation.modules.sources.target import TargetEvidence
from tests.helpers.windows_tree import build_windows_tree, open_virtual_target

Rec = RecordDescriptor("test/rec", [
    ("datetime", "ts"), ("datetime", "other"), ("path", "p"), ("digest", "digest"), ("string[]", "items"),
    ("bytes", "raw"), ("string", "missing"), ("string", "hostname"), ("string", "username"), ("string", "nt"),
])


def spec(**kw):
    base = dict(name="t", function="t", artifact="test", evidence_type="execution", description="d",
                message="{p} items={items} {nope}", user="username")
    base.update(kw)
    return ArtifactSpec(**base)


def rec(**kw):
    base = dict(ts=datetime(2024, 1, 2, 3, 4, 5), other=datetime(2024, 1, 3, tzinfo=timezone.utc),
                p="C:\\Windows\\x.exe", digest=(None, "a" * 40, None), items=["a", "b"], raw=b"\x01\x02",
                missing=None, hostname="PC1", username="bob", nt="deadbeef")
    base.update(kw)
    return Rec(**base)


def test_record_fields_types():
    f = record_fields(rec())
    json.dumps({k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in f.items()})
    assert f["ts"].tzinfo is not None and f["ts"].hour == 3
    assert f["p"] == "C:\\Windows\\x.exe"
    assert f["digest_sha1"] == "a" * 40 and "digest_md5" not in f and "digest" not in f
    assert f["items"] == "a, b"
    assert f["raw"] == "0102"
    assert "hostname" not in f and not any(k.startswith("_") for k in f)


def test_record_to_events_multi_timestamp():
    events = record_to_events(rec(), spec(), "src")
    assert sorted(e.timestamp_desc for e in events) == ["other", "ts"]
    e = events[0]
    assert e.host == "PC1" and e.user == "bob" and e.artifact == "test"
    assert e.evidence_type is EvidenceType.EXECUTION
    assert e.message == "C:\\Windows\\x.exe items=a, b "
    one = record_to_events(rec(), spec(timestamps={"ts": "Last Run"}), "src")
    assert [e.timestamp_desc for e in one] == ["Last Run"]


def test_timestamp_list_field_explodes():
    R2 = RecordDescriptor("test/r2", [("datetime", "ts"), ("datetime[]", "previousruns")])
    r = R2(ts=datetime(2024, 1, 5, tzinfo=timezone.utc),
           previousruns=[datetime(2024, 1, 1, tzinfo=timezone.utc), datetime(2024, 1, 2, tzinfo=timezone.utc)])
    events = record_to_events(r, spec(message="", user=None, timestamps={"ts": "Last Run", "previousruns": "Previous Run"}), "s")
    assert sorted(e.timestamp_desc for e in events) == ["Last Run", "Previous Run", "Previous Run"]


def test_no_timestamp_record():
    events = record_to_events(rec(ts=None, other=None), spec(), "src")
    assert len(events) == 1
    assert events[0].timestamp == datetime(1970, 1, 1, tzinfo=timezone.utc)
    assert events[0].timestamp_desc == "No Timestamp"
    assert "no_timestamp" in events[0].tags


def test_drop_fields():
    events = record_to_events(rec(), spec(drop=("nt",)), "src")
    assert "nt" not in events[0].fields


def test_catalog_valid_and_registered(tmp_path):
    cat = load_catalog()
    names = [s.name for s in cat]
    assert len(names) == len(set(names)) and len(names) >= 30
    reg = ModuleRegistry()
    reg.discover(user_dir=None)
    for s in cat:
        assert reg.get(s.name).spec == s
    sam = next(s for s in cat if s.name == "local_accounts")
    assert {"lm", "nt"} <= set(sam.drop)
    bad = tmp_path / "bad.yaml"
    bad.write_text("- {name: x, function: x, artifact: x, evidence_type: other, description: d, bogus: 1}\n")
    with pytest.raises(ValueError, match="bogus"):
        load_catalog(bad)


@pytest.fixture(scope="module")
def tree(tmp_path_factory):
    return build_windows_tree(tmp_path_factory.mktemp("w") / "C")


def run_module(name, source):
    reg = ModuleRegistry()
    reg.discover(user_dir=None)
    errors = []
    events = list(reg.get(name)().parse(source, Context(), lambda m, s: errors.append(s)))
    return events, errors


@pytest.mark.parametrize("name", ["prefetch", "amcache_files", "shimcache", "bam", "lnk", "srum_app", "services"])
def test_fixture_artifacts(tree, name):
    events, errors = run_module(name, TargetEvidence(open_virtual_target(tree)))
    assert errors == []
    assert events, name
    for e in events[:50]:
        json.dumps(e.to_dict())
    if name == "prefetch":
        assert all(e.evidence_type is EvidenceType.EXECUTION for e in events)
        assert any("MPCMDRUN" in e.message.upper() for e in events)


def test_missing_software_hive_is_silent(tree):
    source = TargetEvidence(open_virtual_target(tree, software=False))
    events, errors = run_module("prefetch", source)
    assert events == [] and errors == []
    events, errors = run_module("shimcache", source)
    assert events and errors == []


def test_directory_source_yields_nothing(tree):
    events, errors = run_module("prefetch", DirectoryEvidence(tree))
    assert events == [] and errors == []
