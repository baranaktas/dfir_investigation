"""Requirement checks that modules declare and the preflight runs."""

from __future__ import annotations

import enum
import importlib.metadata
import os
import platform
import shutil
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping


class Status(enum.Enum):
    OK = "ok"
    MISSING = "missing"
    WARN = "warn"


@dataclass(frozen=True)
class CheckResult:
    requirement: str
    status: Status
    detail: str
    fix: str | None
    mandatory: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "requirement": self.requirement,
            "status": self.status.value,
            "detail": self.detail,
            "fix": self.fix,
            "mandatory": self.mandatory,
        }


@dataclass(frozen=True)
class Context:
    output_dir: Path | None = None
    input_path: Path | None = None
    allow_install: bool = True
    options: Mapping[str, Any] = field(default_factory=dict)


def _version_tuple(v: str) -> tuple[int, ...]:
    out = []
    for part in v.split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        if not digits:
            break
        out.append(int(digits))
        if digits != part:
            break
    return tuple(out)


class Requirement(ABC):
    mandatory: bool = True
    installable: bool = False

    @abstractmethod
    def describe(self) -> str: ...

    @abstractmethod
    def check(self, ctx: Context) -> CheckResult: ...

    def _result(self, status: Status, detail: str, fix: str | None = None) -> CheckResult:
        return CheckResult(self.describe(), status, detail, fix, self.mandatory)

    def _fail(self, detail: str, fix: str | None = None) -> CheckResult:
        return self._result(Status.MISSING if self.mandatory else Status.WARN, detail, fix)


class PythonPackage(Requirement):
    installable = True

    def __init__(self, dist: str, import_name: str, min_version: str | None = None, mandatory: bool = True):
        self.dist = dist
        self.import_name = import_name
        self.min_version = min_version
        self.mandatory = mandatory

    def describe(self) -> str:
        return f"python package {self.dist}" + (f">={self.min_version}" if self.min_version else "")

    def install_spec(self) -> str:
        return f"{self.dist}>={self.min_version}" if self.min_version else self.dist

    def check(self, ctx: Context) -> CheckResult:
        fix = f"pip install {self.install_spec()}"
        try:
            version = importlib.metadata.version(self.dist)
        except importlib.metadata.PackageNotFoundError:
            return self._fail(f"{self.dist} is not installed", fix)
        if self.min_version and _version_tuple(version) < _version_tuple(self.min_version):
            return self._fail(f"{self.dist} {version} is older than required {self.min_version}", fix)
        return self._result(Status.OK, f"{self.dist} {version}")


class ExternalTool(Requirement):
    def __init__(self, name: str, executables: tuple[str, ...], mandatory: bool = True, fix: str | None = None):
        self.name = name
        self.executables = executables
        self.mandatory = mandatory
        self.fix = fix

    def describe(self) -> str:
        return f"tool {self.name}"

    def check(self, ctx: Context) -> CheckResult:
        for exe in self.executables:
            path = shutil.which(exe)
            if path:
                return self._result(Status.OK, path)
        return self._fail(
            f"none of {', '.join(self.executables)} found on PATH",
            self.fix or f"install {self.name} and add it to PATH",
        )


def is_admin() -> bool:
    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


class AdminRights(Requirement):
    def __init__(self, mandatory: bool = True):
        self.mandatory = mandatory

    def describe(self) -> str:
        return "administrator rights"

    def check(self, ctx: Context) -> CheckResult:
        if is_admin():
            return self._result(Status.OK, "running elevated")
        return self._fail(
            "not running as administrator/root",
            "re-run from an elevated prompt (Run as administrator / sudo)",
        )


class Platform(Requirement):
    def __init__(self, systems: tuple[str, ...]):
        self.systems = tuple(s.lower() for s in systems)
        self.mandatory = True

    def describe(self) -> str:
        return f"platform {'/'.join(self.systems)}"

    def check(self, ctx: Context) -> CheckResult:
        current = platform.system().lower()
        if current in self.systems:
            return self._result(Status.OK, current)
        return self._fail(f"running on {current}", f"run this module on {'/'.join(self.systems)}")


class FreeSpace(Requirement):
    def __init__(self, min_bytes: int, mandatory: bool = False):
        self.min_bytes = min_bytes
        self.mandatory = mandatory

    def describe(self) -> str:
        return f"free space >= {self.min_bytes / 2**30:.2f} GiB"

    def check(self, ctx: Context) -> CheckResult:
        path = Path(ctx.output_dir) if ctx.output_dir else Path.cwd()
        while not path.exists() and path != path.parent:
            path = path.parent
        free = shutil.disk_usage(path).free
        if free >= self.min_bytes:
            return self._result(Status.OK, f"{free / 2**30:.2f} GiB free at {path}")
        return self._fail(
            f"only {free / 2**30:.2f} GiB free at {path}",
            "write output to a larger (external) disk with -o/--out",
        )


class PythonVersion(Requirement):
    def __init__(self, min: tuple[int, int] = (3, 12), max_exclusive: tuple[int, int] = (3, 14)):
        self.min = min
        self.max_exclusive = max_exclusive
        self.mandatory = True

    def describe(self) -> str:
        return f"python >={self.min[0]}.{self.min[1]},<{self.max_exclusive[0]}.{self.max_exclusive[1]}"

    def check(self, ctx: Context) -> CheckResult:
        cur = tuple(sys.version_info[:2])
        ver = f"{cur[0]}.{cur[1]}"
        if cur < self.min:
            return self._fail(f"python {ver} is too old", "use Python 3.12 or 3.13")
        if cur >= self.max_exclusive:
            return self._fail(
                f"python {ver}: not supported yet (yara-python has no build for it)",
                "use Python 3.12 or 3.13",
            )
        return self._result(Status.OK, f"python {ver}")


class SigmaRules(Requirement):
    """Optional: the bundled SigmaHQ set, or Sigma rules under INVESTIGATION_HOME/rules/sigma."""

    mandatory = False

    def describe(self) -> str:
        return "Sigma rules (SigmaHQ)"

    def check(self, ctx: Context) -> CheckResult:
        from investigation.core.rules_update import sigma_root, sigma_sources

        src = sigma_sources()
        if src.kind == "none":
            return self._fail(f"no Sigma rules in {sigma_root()}", "investigation rules update")
        n = sum(1 for root in src.paths if root.is_dir() for p in root.rglob("*") if p.suffix in (".yml", ".yaml"))
        return self._result(Status.OK, f"{n} rule files, {src.label}")
