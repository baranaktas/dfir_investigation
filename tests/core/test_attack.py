import re
from datetime import datetime, timezone
from pathlib import Path

from investigation.core.attack import TACTICS, TECHNIQUE_TACTICS, primary_tactic, source_label, tactics_for
from investigation.core.models import Event, Finding, Severity
from investigation.modules.detections.sigma_engine import load_sigma

ROOT = Path(__file__).resolve().parent.parent.parent / "investigation"


def finding(mitre=(), tactics=()):
    return Finding(rule_id="R", title="t", severity=Severity.HIGH, description="d", mitre=tuple(mitre),
                   events=[], tactics=tuple(tactics))


def event(artifact="evtx", source_file="a.evtx"):
    return Event(timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc), timestamp_desc="x", artifact=artifact,
                 source_file=source_file, message="m", fields={})


def test_tactics_end_with_other():
    assert TACTICS[0] == ("reconnaissance", "Reconnaissance")
    assert TACTICS[-1] == ("other", "Other")


def test_every_rule_technique_is_mapped():
    files = list((ROOT / "rules" / "builtin").glob("*.y*ml")) + list((ROOT / "modules" / "detections").glob("*.py"))
    assert files
    found = set()
    for f in files:
        found |= {m.group(0).split(".")[0] for m in re.finditer(r"T\d{4}(\.\d{3})?", f.read_text(errors="replace"))}
    assert found - set(TECHNIQUE_TACTICS) == set()


def test_tactics_for_subtechnique_and_order():
    assert tactics_for(finding(mitre=("T1070.001", "T1562.001"))) == ("defense_evasion",)
    assert tactics_for(finding(mitre=("T1053.005",))) == ("persistence", "execution", "privilege_escalation")


def test_unmapped_is_other():
    assert tactics_for(finding(mitre=("T9999",))) == ("other",)
    assert primary_tactic(finding()) == "other"


def test_sigma_tactic_tags_win():
    assert primary_tactic(finding(mitre=("T1047",), tactics=("lateral_movement",))) == "lateral_movement"


def test_sigma_engine_reads_tactic_tags(tmp_path):
    (tmp_path / "r.yml").write_text(
        "title: T\nid: 11111111-1111-1111-1111-111111111111\nstatus: test\nlevel: high\n"
        "tags: [attack.defense-evasion, attack.persistence, attack.bogus, attack.t1059]\n"
        "logsource: {product: windows, category: process_creation}\n"
        "detection:\n  sel: {Image|endswith: '\\a.exe'}\n  condition: sel\n")
    rules, _ = load_sigma([tmp_path], Severity.LOW)
    assert rules[0].tactics == ("defense_evasion", "persistence")


def test_source_label():
    assert source_label(event(source_file="vss:3:C:/x.evtx")) == "vss:3"
    assert source_label(event(artifact="live_processes")) == "live"
    assert source_label(event(artifact="memory_pslist")) == "memory"
    assert source_label(event()) == "disk"
