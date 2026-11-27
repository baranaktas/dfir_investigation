"""Turn Fox-IT dissect.target plugins into Investigation parser modules.

Every entry of investigation/artifacts/windows.yaml becomes one ParserModule. Each dissect record becomes
one Event per timestamp field (super-timeline style).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar, Iterator, Mapping

import yaml

from investigation.core.models import Event, EvidenceType, json_safe
from investigation.core.module import ErrorSink, ModuleMeta, ModuleType, ParserModule
from investigation.core.registry import register
from investigation.modules.parsers import dissect_patches
from investigation.core.requirements import Context, PythonPackage
from investigation.core.source import EvidenceSource
from investigation.core.frozen import resource

log = logging.getLogger("investigation")

CATALOG = resource("artifacts/windows.yaml")
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
MAX_RECORD_ERRORS = 5
SPEC_KEYS = {
    "name", "function", "kwargs", "artifact", "evidence_type", "description", "message", "user",
    "timestamps", "note", "heavy", "drop", "requires",
}
_SKIP_FIELDS = {"hostname", "domain"}


@dataclass(frozen=True)
class ArtifactSpec:
    name: str
    function: str
    artifact: str
    evidence_type: str
    description: str
    message: str = ""
    user: str | None = None
    timestamps: Any = "auto"
    kwargs: Mapping[str, Any] = field(default_factory=dict)
    note: str | None = None
    heavy: bool = False
    drop: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()


def load_catalog(path: Path | None = None) -> list[ArtifactSpec]:
    path = Path(path) if path else CATALOG
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a list")
    specs: list[ArtifactSpec] = []
    seen: set[str] = set()
    for raw in data:
        if not isinstance(raw, dict):
            raise ValueError(f"{path}: every entry must be a mapping")
        unknown = set(raw) - SPEC_KEYS
        if unknown:
            raise ValueError(f"{path}: {raw.get('name')!r} has unknown keys: {', '.join(sorted(unknown))}")
        for req in ("name", "function", "artifact", "evidence_type", "description"):
            if req not in raw:
                raise ValueError(f"{path}: {raw.get('name')!r} missing {req!r}")
        EvidenceType(raw["evidence_type"])
        ts = raw.get("timestamps", "auto")
        if ts != "auto" and not isinstance(ts, dict):
            raise ValueError(f"{path}: {raw['name']!r} timestamps must be 'auto' or a mapping")
        if raw["name"] in seen:
            raise ValueError(f"{path}: duplicate artifact name {raw['name']!r}")
        seen.add(raw["name"])
        specs.append(ArtifactSpec(
            name=raw["name"], function=raw["function"], artifact=raw["artifact"],
            evidence_type=raw["evidence_type"], description=raw["description"],
            message=raw.get("message") or "", user=raw.get("user"), timestamps=ts,
            kwargs=dict(raw.get("kwargs") or {}), note=raw.get("note"), heavy=bool(raw.get("heavy", False)),
            drop=tuple(raw.get("drop") or ()), requires=tuple(raw.get("requires") or ()),
        ))
    return specs


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _field_names(record: Any) -> list[str]:
    desc = record._desc
    try:
        names = list(desc.get_all_fields())
    except Exception:
        names = list(getattr(desc, "fields", {}))
    return [n for n in names if not n.startswith("_") and n not in _SKIP_FIELDS]


def _is_digest(value: Any) -> bool:
    return all(hasattr(value, a) for a in ("md5", "sha1", "sha256")) and not isinstance(value, (str, bytes))


def _convert(value: Any) -> Any:
    if isinstance(value, datetime):
        return _utc(value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, (list, tuple)):
        return ", ".join(str(_convert(v)) for v in value)
    return json_safe(value)


def record_fields(record: Any, drop: tuple[str, ...] = ()) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name in _field_names(record):
        if name in drop:
            continue
        value = getattr(record, name, None)
        if value is None:
            continue
        if _is_digest(value):
            for algo in ("md5", "sha1", "sha256"):
                h = getattr(value, algo, None)
                if h:
                    out[f"{name}_{algo}"] = str(h)
            continue
        if isinstance(value, (list, tuple)) and value and all(isinstance(v, datetime) for v in value):
            out[name] = ", ".join(_utc(v).isoformat() for v in value)
            continue
        out[name] = _convert(value)
    return out


class _Default(dict):
    def __missing__(self, key: str) -> str:
        return ""


def _timestamps(record: Any, spec: ArtifactSpec) -> list[tuple[datetime, str]]:
    found: list[tuple[datetime, str]] = []
    if spec.timestamps == "auto":
        wanted = {n: n for n in _field_names(record)}
    else:
        wanted = dict(spec.timestamps)
    for name, desc in wanted.items():
        value = getattr(record, name, None) if name in _field_names(record) else None
        values = value if isinstance(value, (list, tuple)) else [value]
        for v in values:
            if isinstance(v, datetime) and v.year > 1601:
                found.append((_utc(v), desc))
    return found


def record_to_events(record: Any, spec: ArtifactSpec, source_file: str) -> list[Event]:
    fields = record_fields(record, spec.drop)
    flat = {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in fields.items()}
    message = spec.message.format_map(_Default({k: "" if v is None else v for k, v in flat.items()})) if spec.message \
        else " ".join(f"{k}={v}" for k, v in list(flat.items())[:4])
    host = getattr(record, "hostname", None) if "hostname" in getattr(record._desc, "fields", {}) else None
    user = flat.get(spec.user) if spec.user else None
    src = ""
    try:
        src = str(record._source or "")
    except Exception:
        pass
    common = dict(
        artifact=spec.artifact, source_file=src or spec.function, message=message[:500],
        host=str(host) if host else None, user=str(user) if user not in (None, "") else None,
        fields=flat, evidence_type=EvidenceType(spec.evidence_type),
    )
    stamps = _timestamps(record, spec)
    if not stamps:
        return [Event(timestamp=EPOCH, timestamp_desc="No Timestamp", tags=("no_timestamp",), **common)]
    return [Event(timestamp=ts, timestamp_desc=desc, **common) for ts, desc in stamps]


def _resolve_function(target: Any, path: str):
    fn = target
    for part in path.split("."):
        fn = getattr(fn, part)
    return fn


class DissectArtifact(ParserModule):
    spec: ClassVar[ArtifactSpec]

    def parse(self, source: EvidenceSource, ctx: Context, errors: ErrorSink) -> Iterator[Event]:
        target = getattr(source, "target", None)
        if target is None:
            return
        from dissect.target.exceptions import PluginError, UnsupportedPluginError

        spec = self.spec
        try:
            fn = _resolve_function(target, spec.function)
            records = iter(fn(**spec.kwargs))
        except (UnsupportedPluginError, PluginError) as exc:
            log.debug("%s: not available on this evidence: %s", spec.name, exc)
            return
        except Exception as exc:
            errors(spec.name, f"cannot run dissect function {spec.function}: {type(exc).__name__}: {exc}")
            return
        bad = 0
        while True:
            try:
                record = next(records)
            except StopIteration:
                return
            except (UnsupportedPluginError, PluginError) as exc:
                log.debug("%s: not available on this evidence: %s", spec.name, exc)
                return
            except Exception as exc:
                errors(spec.name, f"stopped reading: {type(exc).__name__}: {exc}")
                return
            try:
                yield from record_to_events(record, spec, spec.function)
            except Exception as exc:
                bad += 1
                if bad <= MAX_RECORD_ERRORS:
                    errors(spec.name, f"bad record: {type(exc).__name__}: {exc}")


def _make_module(spec: ArtifactSpec) -> type[DissectArtifact]:
    meta = ModuleMeta(
        name=spec.name,
        description=spec.description,
        type=ModuleType.PARSER,
        requirements=(
            PythonPackage("dissect.target", "dissect.target", min_version="3.20"),
            *(PythonPackage(dist, dist) for dist in spec.requires),
        ),
        artifacts=(spec.artifact,),
    )
    return type(f"Artifact_{spec.name}", (DissectArtifact,), {"spec": spec, "meta": meta})


CATALOG_MODULES = [register(_make_module(s)) for s in load_catalog()]
