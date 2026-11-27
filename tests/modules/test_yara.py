import hashlib
from pathlib import Path

import pytest

from investigation.core.models import Severity
from investigation.core.requirements import Context
from investigation.core.store import EventStore
from investigation.modules.detections.yara_findings import YaraFindings
from investigation.modules.parsers import yara_scan
from investigation.modules.parsers.yara_scan import YaraScanner
from investigation.modules.sources.directory import DirectoryEvidence
from investigation.modules.sources.target import TargetEvidence
from tests.helpers.windows_tree import build_windows_tree, open_virtual_target

WEBSHELL = b"<?php eval(base64_decode($_POST['x'])); system($_GET['c']); ?>"
MIMI = b"MZ\x90\x00" + b"\x00" * 64 + b"sekurlsa::logonpasswords gentilkiwi"


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


def scan(source, **opts):
    errors = []
    events = list(YaraScanner().parse(source, Context(options=opts), lambda m, s: errors.append(s)))
    return events, errors


@pytest.fixture
def evidence(tmp_path):
    d = tmp_path / "ev"
    (d / "www").mkdir(parents=True)
    (d / "www" / "shell.php").write_bytes(WEBSHELL)
    (d / "tool.exe").write_bytes(MIMI)
    (d / "notes.txt").write_text("meeting notes")
    big = d / "big.bin"
    with big.open("wb") as f:
        f.write(b"sekurlsa::logonpasswords")
        f.truncate(60 * 1024 * 1024)
    return d


def test_scan_directory(evidence):
    events, errors = scan(DirectoryEvidence(evidence))
    assert errors == []
    by_path = {e.fields["path"]: e for e in events}
    assert set(by_path) == {"www/shell.php", "tool.exe"}
    assert by_path["www/shell.php"].fields["rule"] == "INV_Webshell_PHP_Generic"
    assert by_path["tool.exe"].fields["sha256"] == hashlib.sha256(MIMI).hexdigest()
    assert by_path["tool.exe"].artifact == "yara"
    assert by_path["tool.exe"].timestamp.tzinfo is not None


def test_findings_severity_from_meta(evidence, tmp_path):
    events, _ = scan(DirectoryEvidence(evidence))
    store = EventStore(tmp_path / "db")
    store.add_many(events)
    findings = {f.rule_id: f for f in YaraFindings().detect(store, Context())}
    assert findings["YARA-INV_Mimikatz_Strings"].severity is Severity.CRITICAL
    assert "T1003.001" in findings["YARA-INV_Mimikatz_Strings"].mitre
    assert findings["YARA-INV_Webshell_PHP_Generic"].severity is Severity.HIGH


def test_bad_user_rule_file_skipped(evidence, home):
    (home / "rules" / "yara").mkdir(parents=True)
    (home / "rules" / "yara" / "bad.yar").write_text("rule broken { condition: }")
    (home / "rules" / "yara" / "mine.yar").write_text('rule Mine_Notes { strings: $a = "meeting" condition: $a }')
    events, errors = scan(DirectoryEvidence(evidence))
    assert any("bad.yar" in e for e in errors)
    assert {e.fields["rule"] for e in events} >= {"Mine_Notes", "INV_Mimikatz_Strings"}


def test_max_files_reported(evidence, monkeypatch):
    monkeypatch.setattr(yara_scan, "MAX_FILES", 2)
    events, errors = scan(DirectoryEvidence(evidence))
    assert any("file limit" in e for e in errors)


def test_system_source_scans_only_suspicious_paths(tmp_path):
    tree = build_windows_tree(tmp_path / "C")
    (tree / "Users" / "IEUser" / "Downloads").mkdir(parents=True)
    (tree / "Users" / "IEUser" / "Downloads" / "a.php").write_bytes(WEBSHELL)
    (tree / "Windows" / "System32" / "b.php").write_bytes(WEBSHELL)
    (tree / "inetpub" / "wwwroot").mkdir(parents=True)
    (tree / "inetpub" / "wwwroot" / "c.aspx").write_bytes(
        b'<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe", Request.Form["c"]); %>')
    events, errors = scan(TargetEvidence(open_virtual_target(tree)))
    paths = sorted(e.fields["path"].casefold() for e in events)
    assert paths == ["inetpub/wwwroot/c.aspx", "users/ieuser/downloads/a.php"]
