"""Preflight: check every selected module's requirements, auto-install what can be installed,
and decide which modules can run."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Callable

from investigation.core.module import BaseModule
from investigation.core.requirements import (
    CheckResult,
    Context,
    PythonPackage,
    PythonVersion,
    Requirement,
    Status,
)

Installer = Callable[[list[str]], bool]


@dataclass
class PreflightReport:
    results: dict[str, list[CheckResult]] = field(default_factory=dict)
    runnable: list[type[BaseModule]] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)
    installed: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.skipped and not any(
            r.status is Status.MISSING for rs in self.results.values() for r in rs
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "results": {k: [r.to_dict() for r in v] for k, v in self.results.items()},
            "runnable": [m.meta.name for m in self.runnable],
            "skipped": dict(self.skipped),
            "installed": list(self.installed),
        }


def pip_installer(dists: list[str]) -> bool:
    proc = subprocess.run([sys.executable, "-m", "pip", "install", *dists])
    return proc.returncode == 0


def _safe_check(req: Requirement, ctx: Context) -> CheckResult:
    try:
        return req.check(ctx)
    except Exception as exc:
        return CheckResult(req.describe(), Status.MISSING, f"check failed: {type(exc).__name__}: {exc}", None, True)


def _is_blocking(r: CheckResult) -> bool:
    return r.status is Status.MISSING and r.mandatory


def run_preflight(
    modules: list[type[BaseModule]],
    ctx: Context,
    installer: Installer | None = None,
) -> PreflightReport:
    report = PreflightReport()
    report.results["framework"] = [_safe_check(PythonVersion(), ctx)]

    reqs: dict[str, list[Requirement]] = {m.meta.name: m.all_requirements() for m in modules}
    for m in modules:
        report.results[m.meta.name] = [_safe_check(r, ctx) for r in reqs[m.meta.name]]

    can_install = ctx.allow_install and not getattr(sys, "frozen", False) and installer is not None
    if can_install:
        to_install: list[str] = []
        for m in modules:
            for req, res in zip(reqs[m.meta.name], report.results[m.meta.name]):
                if _is_blocking(res) and isinstance(req, PythonPackage):
                    spec = req.install_spec()
                    if spec not in to_install:
                        to_install.append(spec)
        if to_install and installer(to_install):
            report.installed = to_install
            for m in modules:
                report.results[m.meta.name] = [
                    _safe_check(req, ctx) if isinstance(req, PythonPackage) and _is_blocking(res) else res
                    for req, res in zip(reqs[m.meta.name], report.results[m.meta.name])
                ]

    for m in modules:
        name = m.meta.name
        blocking = [r for r in report.results[name] if _is_blocking(r)]
        if blocking:
            report.skipped[name] = blocking[0].detail
            continue
        dead = [d for d in m.meta.depends_on if d in report.skipped]
        if dead:
            report.skipped[name] = f"depends on skipped module {dead[0]}"
            continue
        report.runnable.append(m)
    return report
