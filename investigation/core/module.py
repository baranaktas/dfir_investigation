"""Module base classes. Every capability of the framework is one module."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, ClassVar, Iterator

from investigation.core.models import Event, Finding
from investigation.core.requirements import AdminRights, Context, Platform, Requirement

if TYPE_CHECKING:
    from investigation.core.result import AnalysisResult
    from investigation.core.source import EvidenceSource
    from investigation.core.store import EventStore


class ModuleType(enum.Enum):
    COLLECTOR = "collector"
    SOURCE = "source"
    PARSER = "parser"
    DETECTION = "detection"
    OUTPUT = "output"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class ModuleMeta:
    name: str
    description: str
    type: ModuleType
    platforms: tuple[str, ...] = ("any",)
    requires_admin: bool = False
    requirements: tuple[Requirement, ...] = ()
    depends_on: tuple[str, ...] = ()
    artifacts: tuple[str, ...] = ()
    mitre: tuple[str, ...] = ()
    priority: int = 100
    category: str = ""
    confirm: str = ""


ErrorSink = Callable[[str, str], None]
"""(module_name, message) -> None"""


class BaseModule:
    meta: ClassVar[ModuleMeta]

    @classmethod
    def all_requirements(cls) -> list[Requirement]:
        reqs: list[Requirement] = list(cls.meta.requirements)
        if "any" not in cls.meta.platforms:
            reqs.append(Platform(cls.meta.platforms))
        if cls.meta.requires_admin:
            reqs.append(AdminRights())
        return reqs


class SourceModule(BaseModule):
    def can_open(self, path: Path) -> bool:
        raise NotImplementedError

    def open(self, path: Path) -> "EvidenceSource":
        raise NotImplementedError


class ParserModule(BaseModule):
    def parse(self, source: "EvidenceSource", ctx: Context, errors: ErrorSink) -> Iterator[Event]:
        raise NotImplementedError


class DetectionModule(BaseModule):
    def detect(self, store: "EventStore", ctx: Context, errors: ErrorSink | None = None) -> Iterator[Finding]:
        raise NotImplementedError


class OutputModule(BaseModule):
    def write(self, result: "AnalysisResult", out_dir: Path, ctx: Context) -> list[Path]:
        raise NotImplementedError


class CollectorModule(BaseModule):
    """Live-system collection. Must not spawn processes or touch the network; writes under `out_dir`."""

    def collect(self, ctx: Context, out_dir: Path) -> None:
        raise NotImplementedError
