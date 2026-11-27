"""YARA scanning of suspicious locations (Temp, Downloads, Public, web roots, ...)."""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from investigation.core.models import Event, EvidenceType
from investigation.core.module import ErrorSink, ModuleMeta, ModuleType, ParserModule
from investigation.core.registry import investigation_home, register
from investigation.core.requirements import Context, PythonPackage
from investigation.core.source import EvidenceSource
from investigation.core.frozen import resource

log = logging.getLogger("investigation")
BUILTIN_RULES = resource("rules/yara")
MAX_FILE = 50 * 1024 * 1024
MAX_FILES = 20_000
TIMEOUT = 30
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ROAMING_EXT = ("exe", "dll", "ps1", "bat", "vbs", "js", "hta")
SCAN_GLOBS = [
    "users/*/appdata/local/temp/**",
    "users/*/downloads/**",
    "users/*/desktop/**",
    *[f"users/*/appdata/roaming/**/*.{ext}" for ext in _ROAMING_EXT],
    "users/public/**",
    "programdata/*/*",
    "windows/temp/**",
    "perflogs/**",
    "inetpub/wwwroot/**",
    "$recycle.bin/**",
]


def rule_files() -> list[Path]:
    files = sorted(BUILTIN_RULES.glob("*.yar"))
    user = investigation_home() / "rules" / "yara"
    if user.is_dir():
        files += sorted(p for p in user.rglob("*") if p.suffix.casefold() in (".yar", ".yara") and p.is_file())
    return files


def compile_rules(errors: ErrorSink) -> list[Any]:
    import yara

    compiled = []
    for f in rule_files():
        try:
            compiled.append(yara.compile(filepath=str(f), externals={"filepath": ""}))
        except Exception as exc:
            errors("yara", f"rule file {f.name} skipped: {exc}")
    return compiled


@register
class YaraScanner(ParserModule):
    meta = ModuleMeta(
        name="yara",
        description="YARA scan of suspicious locations (Temp, Downloads, Public, ProgramData, web roots, ...)",
        type=ModuleType.PARSER,
        requirements=(PythonPackage("yara-python", "yara", min_version="4.3"),),
        artifacts=("yara",),
    )

    def _candidates(self, source: EvidenceSource, ctx: Context) -> Iterator[str]:
        patterns = (SCAN_GLOBS if source.is_system else ["**/*"]) + list(ctx.options.get("yara_paths", []))
        seen: set[str] = set()
        for pattern in patterns:
            for path in source.glob(pattern):
                if path not in seen:
                    seen.add(path)
                    yield path

    def parse(self, source: EvidenceSource, ctx: Context, errors: ErrorSink) -> Iterator[Event]:
        rules = compile_rules(errors)
        if not rules:
            return
        scanned = 0
        for path in self._candidates(source, ctx):
            if scanned >= MAX_FILES:
                errors(self.meta.name, f"file limit of {MAX_FILES} reached; remaining files not scanned")
                return
            size, mtime = source.stat(path)
            if size is not None and size > MAX_FILE:
                continue
            try:
                with source.open(path) as fh:
                    data = fh.read(MAX_FILE + 1)
            except Exception as exc:
                errors(self.meta.name, f"{path}: cannot read: {exc}")
                continue
            if len(data) > MAX_FILE:
                continue
            scanned += 1
            matches = []
            for compiled in rules:
                try:
                    matches += compiled.match(data=data, timeout=TIMEOUT, externals={"filepath": path})
                except Exception as exc:
                    errors(self.meta.name, f"{path}: scan failed: {exc}")
            if not matches:
                continue
            sha256 = hashlib.sha256(data).hexdigest()
            for m in matches:
                meta = dict(m.meta or {})
                yield Event(
                    timestamp=mtime or EPOCH,
                    timestamp_desc="File Modified (YARA match)" if mtime else "No Timestamp",
                    artifact="yara",
                    source_file=path,
                    message=f"YARA {m.rule} matched {path}",
                    fields={
                        "rule": m.rule, "namespace": m.namespace, "tags": ", ".join(m.tags),
                        "severity": str(meta.get("severity", "high")), "mitre": str(meta.get("mitre", "")),
                        "description": str(meta.get("description", "")), "path": path, "sha256": sha256,
                        "size": len(data),
                    },
                    tags=() if mtime else ("no_timestamp",),
                    evidence_type=EvidenceType.EXISTENCE,
                )
