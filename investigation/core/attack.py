"""ATT&CK tactic mapping and event source labels for the report."""
from __future__ import annotations

from investigation.core.models import Event, Finding

TACTICS: tuple[tuple[str, str], ...] = (
    ("reconnaissance", "Reconnaissance"),
    ("resource_development", "Resource Development"),
    ("initial_access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege_escalation", "Privilege Escalation"),
    ("defense_evasion", "Defense Evasion"),
    ("credential_access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral_movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command_and_control", "Command and Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
    ("other", "Other"),
)

TACTIC_SLUGS = frozenset(s for s, _ in TACTICS)

TECHNIQUE_TACTICS: dict[str, tuple[str, ...]] = {
    "T1003": ("credential_access",),
    "T1014": ("defense_evasion",),
    "T1021": ("lateral_movement",),
    "T1036": ("defense_evasion",),
    "T1047": ("execution",),
    "T1052": ("exfiltration",),
    "T1053": ("persistence", "execution", "privilege_escalation"),
    "T1055": ("defense_evasion", "privilege_escalation"),
    "T1059": ("execution",),
    "T1070": ("defense_evasion",),
    "T1071": ("command_and_control",),
    "T1078": ("initial_access", "persistence", "privilege_escalation", "defense_evasion"),
    "T1087": ("discovery",),
    "T1091": ("initial_access", "lateral_movement"),
    "T1098": ("persistence", "privilege_escalation"),
    "T1105": ("command_and_control",),
    "T1110": ("credential_access",),
    "T1136": ("persistence",),
    "T1204": ("execution",),
    "T1218": ("defense_evasion",),
    "T1219": ("command_and_control",),
    "T1482": ("discovery",),
    "T1486": ("impact",),
    "T1490": ("impact",),
    "T1505": ("persistence",),
    "T1543": ("persistence", "privilege_escalation"),
    "T1546": ("persistence", "privilege_escalation"),
    "T1547": ("persistence", "privilege_escalation"),
    "T1550": ("lateral_movement", "defense_evasion"),
    "T1558": ("credential_access",),
    "T1562": ("defense_evasion",),
    "T1567": ("exfiltration",),
    "T1569": ("execution",),
    "T1588": ("resource_development",),
}


def tactics_for(finding: Finding) -> tuple[str, ...]:
    out = list(finding.tactics)
    for tid in finding.mitre:
        out.extend(TECHNIQUE_TACTICS.get(tid.split(".")[0].upper(), ()))
    return tuple(dict.fromkeys(out)) or ("other",)


def primary_tactic(finding: Finding) -> str:
    return tactics_for(finding)[0]


def source_label(event: Event) -> str:
    sf = event.source_file or ""
    if sf.startswith("vss:"):
        parts = sf.split(":", 2)
        if len(parts) == 3 and parts[1].isdigit():
            return f"vss:{parts[1]}"
    if event.artifact.startswith("live_"):
        return "live"
    if event.artifact.startswith("memory_"):
        return "memory"
    return "disk"
