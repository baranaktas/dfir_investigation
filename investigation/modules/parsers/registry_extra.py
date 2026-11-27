"""Registry artifacts that dissect.target has no plugin for: WordWheelQuery and TypedPaths."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Iterator

from investigation.core.models import Event, EvidenceType
from investigation.core.module import ErrorSink, ModuleMeta, ModuleType, ParserModule
from investigation.core.registry import register
from investigation.core.requirements import Context, PythonPackage
from investigation.core.source import EvidenceSource

log = logging.getLogger("investigation")
EXPLORER = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
REQ = (PythonPackage("dissect.target", "dissect.target", min_version="3.20"),)


def _user_keys(target: Any, path: str):
    """Yield (key, username) for every user hive that has `path`."""
    from dissect.target.exceptions import RegistryError

    try:
        keys = list(target.registry.keys(path))
    except RegistryError:
        return
    except Exception as exc:
        log.debug("registry lookup %s failed: %s", path, exc)
        return
    for key in keys:
        user = None
        try:
            rec = target.registry.get_user(key)
            user = getattr(rec, "name", None)
        except Exception:
            pass
        yield key, user


def _decode(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-16-le", "replace").split("\x00", 1)[0]
    return str(value)


def _numbered(values: dict[str, Any]) -> dict[int, str]:
    """Values named with ASCII digits only ('²' is .isdigit() but not int()-able)."""
    return {int(n): _decode(v) for n, v in values.items() if n.isascii() and n.isdigit()}


def _mru_order(raw: Any) -> list[int]:
    if not isinstance(raw, (bytes, bytearray)):
        return []
    order = []
    for i in range(0, len(raw) - 3, 4):
        n = int.from_bytes(raw[i:i + 4], "little")
        if n == 0xFFFFFFFF:
            break
        order.append(n)
    return order


EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _key_ts(key: Any) -> tuple[datetime, tuple[str, ...]]:
    """The key's last-write time, or the 'no timestamp' convention when the hive has none."""
    try:
        ts = key.ts
    except Exception:
        ts = None
    if not isinstance(ts, datetime):
        return EPOCH, ("no_timestamp",)
    return (ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts), ()


@register
class WordWheelQuery(ParserModule):
    meta = ModuleMeta(
        name="wordwheelquery",
        description="WordWheelQuery - terms searched in Explorer's search box, most recent first",
        type=ModuleType.PARSER,
        requirements=REQ,
        artifacts=("wordwheelquery",),
    )

    def parse(self, source: EvidenceSource, ctx: Context, errors: ErrorSink) -> Iterator[Event]:
        target = getattr(source, "target", None)
        if target is None:
            return
        for key, user in _user_keys(target, f"{EXPLORER}\\WordWheelQuery"):
            try:
                values = {v.name: v.value for v in key.values()}
                terms = _numbered(values)
                order = [i for i in _mru_order(values.get("MRUListEx")) if i in terms]
                order += [i for i in sorted(terms) if i not in order]
                ts, tags = _key_ts(key)
            except Exception as exc:
                errors(self.meta.name, f"{key.path}: {type(exc).__name__}: {exc}")
                continue
            for pos, idx in enumerate(order):
                yield Event(
                    timestamp=ts,
                    timestamp_desc="Key Last Written (most recent search)",
                    artifact="wordwheelquery",
                    source_file="NTUSER.DAT",
                    message=f'search: "{terms[idx]}"',
                    host=None,
                    user=user,
                    fields={"term": terms[idx], "mru_position": pos, "value_name": str(idx)},
                    evidence_type=EvidenceType.USER_ACTIVITY,
                    tags=tags,
                )


@register
class TypedPaths(ParserModule):
    meta = ModuleMeta(
        name="typedpaths",
        description="TypedPaths - paths typed into Explorer's address bar",
        type=ModuleType.PARSER,
        requirements=REQ,
        artifacts=("typedpaths",),
    )

    def parse(self, source: EvidenceSource, ctx: Context, errors: ErrorSink) -> Iterator[Event]:
        target = getattr(source, "target", None)
        if target is None:
            return
        for key, user in _user_keys(target, f"{EXPLORER}\\TypedPaths"):
            try:
                entries = sorted(
                    ((int(v.name[3:]), str(v.value)) for v in key.values()
                     if v.name.lower().startswith("url") and v.name[3:].isdigit()),
                )
                ts, tags = _key_ts(key)
            except Exception as exc:
                errors(self.meta.name, f"{key.path}: {type(exc).__name__}: {exc}")
                continue
            for pos, (_, path) in enumerate(entries):
                yield Event(
                    timestamp=ts,
                    timestamp_desc="Key Last Written (most recent path)",
                    artifact="typedpaths",
                    source_file="NTUSER.DAT",
                    message=f"typed path: {path}",
                    user=user,
                    fields={"path": path, "mru_position": pos},
                    evidence_type=EvidenceType.USER_ACTIVITY,
                    tags=tags,
                )
