"""The result of one analysis run, handed to output modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from investigation.core.artefacts import Collector
from investigation.core.models import Finding
from investigation.core.preflight import PreflightReport
from investigation.core.store import EventStore


@dataclass
class AnalysisResult:
    case: dict[str, str]
    store: EventStore
    findings: list[Finding]
    preflight: PreflightReport
    module_errors: list[tuple[str, str]] = field(default_factory=list)
    modules_run: list[str] = field(default_factory=list)
    stories: list[Any] = field(default_factory=list)
    notes: dict[str, str] = field(default_factory=dict)
    collector: Collector | None = None
    artefact_findings: list[Finding] = field(default_factory=list)
    suppressed: list[Any] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-int(f.severity), f.rule_id))
