"""Run Sigma rules (SigmaHQ or your own) against the event timeline."""

from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, ClassVar, Iterator

from investigation.core.models import Event, Finding, Severity
from investigation.core.module import DetectionModule, ErrorSink, ModuleMeta, ModuleType
from investigation.core.registry import investigation_home, register
from investigation.core.requirements import Context, PythonPackage, SigmaRules
from investigation.core.rules_update import sigma_rules_present, update_sigma
from investigation.core.store import EventStore
from investigation.modules.detections.sigma_engine import FIELD_MAP_4688, CompiledRule, load_sigma

log = logging.getLogger("investigation")
MAX_EVENTS_PER_FINDING = 500


def sigma_dir() -> Path:
    return investigation_home() / "rules" / "sigma"


def sigma_paths(ctx: Context) -> list[Path]:
    paths = [Path(p) for p in ctx.options.get("sigma_paths", [])]
    return paths or [sigma_dir()]


@register
class SigmaDetection(DetectionModule):
    meta = ModuleMeta(
        name="sigma",
        description="Sigma rules (SigmaHQ + your own) evaluated natively on Windows event logs",
        type=ModuleType.DETECTION,
        requirements=(PythonPackage("pysigma", "sigma", min_version="1.0"), SigmaRules()),
    )
    last_stats: ClassVar[dict[str, int]] = {}

    def detect(self, store: EventStore, ctx: Context, errors: ErrorSink | None = None) -> Iterator[Finding]:
        errors = errors or (lambda m, s: None)
        min_level = Severity.parse(ctx.options.get("sigma_min_level", "medium"))
        if not ctx.options.get("sigma_paths") and not sigma_rules_present():
            import sys

            if ctx.allow_install and not getattr(sys, "frozen", False):
                try:
                    stats = update_sigma()
                    log.info("downloaded %d SigmaHQ rules", stats["rules"])
                except Exception as exc:
                    errors("sigma", f"no Sigma rules and download failed: {exc}; run 'investigation rules update'")
            else:
                log.warning("no Sigma rules installed; run 'investigation rules update'")
        rules, stats = load_sigma(sigma_paths(ctx), min_level)
        SigmaDetection.last_stats = stats
        if not rules:
            return

        exact: dict[tuple[str, int], list[tuple[CompiledRule, bool]]] = defaultdict(list)
        channel_wide: dict[str, list[tuple[CompiledRule, bool]]] = defaultdict(list)
        for r in rules:
            for channel, eid, mapped in r.routes:
                if eid is None:
                    channel_wide[channel].append((r, mapped))
                else:
                    exact[(channel, eid)].append((r, mapped))

        hits: dict[str, list[Event]] = defaultdict(list)
        by_id = {r.id: r for r in rules}
        for e in store.iter_events(artifact="evtx"):
            channel = str(e.fields.get("Channel") or "")
            try:
                eid = int(e.fields.get("EventID"))
            except (TypeError, ValueError):
                eid = -1
            candidates = exact.get((channel, eid), []) + channel_wide.get(channel, [])
            for rule, mapped in candidates:
                try:
                    if rule.matches(e, FIELD_MAP_4688 if mapped else {}):
                        if len(hits[rule.id]) < MAX_EVENTS_PER_FINDING:
                            hits[rule.id].append(e)
                except Exception as exc:
                    errors("sigma", f"rule {rule.title} failed: {type(exc).__name__}: {exc}")
        for rid, events in hits.items():
            r = by_id[rid]
            yield Finding(
                rule_id=f"SIGMA-{r.id[:8]}",
                title=r.title,
                severity=r.level,
                description=r.description or f"Sigma rule {r.path}",
                mitre=r.mitre,
                tactics=r.tactics,
                events=events,
                note=f"Sigma rule: {Path(r.path).name}",
            )
