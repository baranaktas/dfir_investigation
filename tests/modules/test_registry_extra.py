import pytest

from investigation.core.models import EvidenceType
from investigation.core.requirements import Context
from investigation.modules.parsers.registry_extra import TypedPaths, WordWheelQuery
from investigation.modules.sources.directory import DirectoryEvidence
from investigation.modules.sources.target import TargetEvidence
from tests.helpers.windows_tree import add_user_hive, build_windows_tree, open_virtual_target, user_hive

EXPLORER = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"


def mru_list(*indexes):
    return b"".join(i.to_bytes(4, "little") for i in indexes) + b"\xff\xff\xff\xff"


@pytest.fixture
def target(tmp_path):
    t = open_virtual_target(build_windows_tree(tmp_path / "C"))
    add_user_hive(t, user_hive({
        f"{EXPLORER}\\WordWheelQuery": {
            "0": "secret.docx".encode("utf-16-le") + b"\x00\x00",
            "1": "passwords".encode("utf-16-le") + b"\x00\x00",
            "MRUListEx": mru_list(1, 0),
        },
        f"{EXPLORER}\\TypedPaths": {"url1": "\\\\fileserver\\share", "url2": "C:\\Users\\Public"},
    }))
    return t


def run(module, source):
    errors = []
    events = list(module().parse(source, Context(), lambda m, s: errors.append(s)))
    assert errors == []
    return events


def test_wordwheelquery(target):
    events = run(WordWheelQuery, TargetEvidence(target))
    assert [e.fields["term"] for e in events] == ["passwords", "secret.docx"]
    assert events[0].fields["mru_position"] == 0
    assert events[0].user == "IEUser"
    assert events[0].artifact == "wordwheelquery"
    assert events[0].evidence_type is EvidenceType.USER_ACTIVITY
    assert 'search: "passwords"' in events[0].message
    assert events[0].timestamp.tzinfo is not None


def test_typedpaths(target):
    events = run(TypedPaths, TargetEvidence(target))
    assert [e.fields["path"] for e in events] == ["\\\\fileserver\\share", "C:\\Users\\Public"]
    assert events[0].message == "typed path: \\\\fileserver\\share"
    assert events[0].user == "IEUser"


def test_absent_keys_and_plain_directory(tmp_path):
    tree = build_windows_tree(tmp_path / "C")
    assert run(WordWheelQuery, TargetEvidence(open_virtual_target(tree))) == []
    assert run(TypedPaths, DirectoryEvidence(tree)) == []
