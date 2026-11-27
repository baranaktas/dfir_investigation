"""The collection pipeline: select collectors -> preflight -> run each -> manifest."""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from investigation import __version__
from investigation.core.console import say as _say
from investigation.core.frozen import is_frozen
from investigation.core.module import ModuleType
from investigation.core.package import LOG_NAME, hash_file, write_manifest
from investigation.core.preflight import run_preflight
from investigation.core.registry import ModuleRegistry
from investigation.core.requirements import Context

log = logging.getLogger("investigation.collect")

DEFAULT_CATEGORIES = ("live", "files")


@dataclass
class CollectResult:
    root: Path
    manifest: dict
    exit_code: int


def default_parent() -> Path:
    return Path(sys.executable).parent if getattr(sys, "frozen", False) else Path.cwd()


def collector_identity() -> dict[str, str]:
    """Name and sha256 of the running executable (frozen builds only), so analysis can tell the events the
    collection itself caused."""
    if not is_frozen():
        return {}
    try:
        exe = Path(sys.executable)
        return {"name": exe.name, "sha256": hash_file(exe)["sha256"]}
    except OSError:
        return {}


def package_dir_name(hostname: str, when: datetime) -> str:
    host = re.sub(r"[^A-Za-z0-9._-]", "_", hostname)
    return f"INV_{host}_{when.astimezone(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"


def system_drive_warning(out: Path) -> str | None:
    if os.name != "nt":
        return None
    drive = Path(out).resolve().drive
    system = os.environ.get("SystemDrive", "")
    if system and drive.lower() == system.lower():
        return (f"output is on the system drive ({drive}); writing here alters the evidence disk. "
                "Use an external drive with --out.")
    return None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _select(reg: ModuleRegistry, selection: Sequence[str] | None) -> list:
    collectors = reg.by_type(ModuleType.COLLECTOR)
    if selection is None:
        chosen = [c for c in collectors if c.meta.category in DEFAULT_CATEGORIES]
    else:
        chosen = []
        for token in selection:
            matched = [c for c in collectors if token in (c.meta.name, c.meta.category)]
            if not matched:
                raise KeyError(f"unknown collector or category {token!r}")
            chosen.extend(c for c in matched if c not in chosen)
    return sorted(chosen, key=lambda c: (c.meta.priority, c.meta.name))


def collect(
    selection: Sequence[str] | None,
    out: Path | None = None,
    case_id: str = "",
    examiner: str = "",
    confirm: Callable[[str], bool] = lambda _: False,
    registry: ModuleRegistry | None = None,
    now: Callable[[], datetime] = _utcnow,
    options: Mapping[str, Any] | None = None,
    declined_detail: str = "declined by examiner",
) -> CollectResult:
    if registry is None:
        registry = ModuleRegistry()
        registry.discover(user_dir=None, entry_points=False)
    selected = _select(registry, selection)

    started = now()
    hostname = socket.gethostname()
    parent = Path(out) if out is not None else default_parent()
    root = parent / package_dir_name(hostname, started)
    root.mkdir(parents=True, exist_ok=False)

    handler = logging.FileHandler(root / LOG_NAME, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    old_propagate, log.propagate = log.propagate, False
    try:
        return _run(root, selected, registry, started, hostname, case_id, examiner, confirm, now, options, declined_detail)
    finally:
        log.propagate = old_propagate
        log.removeHandler(handler)
        handler.close()


def _run(root, selected, registry, started, hostname, case_id, examiner, confirm, now, options=None,
         declined_detail: str = "declined by examiner") -> CollectResult:
    extra_files: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    details: dict[str, str] = {}
    ctx = Context(output_dir=root, allow_install=False,
                  options={**(options or {}), "package_root": root, "extra_files": extra_files,
                           "warnings": warnings, "module_detail": details})
    records: dict[str, dict[str, Any]] = {}
    preflight_dict: dict[str, Any] = {}
    state = {"aborted": False}
    crash: BaseException | None = None

    def record(cls, status: str, detail: str = "", seconds: float = 0.0) -> None:
        records[cls.meta.name] = {"name": cls.meta.name, "category": cls.meta.category,
                                  "status": status, "detail": detail, "seconds": round(seconds, 3)}
        suffix = f" ({detail}, {seconds:.1f}s)" if status == "ok" and detail else \
            (f" ({detail})" if detail else "")
        line = f"[{status}] {cls.meta.name}{suffix}"
        _say(line)
        log.info(line) if status == "ok" else log.warning(line)

    try:
        for origin, msg in registry.load_errors:
            log.warning("module load error %s: %s", origin, msg)
        warn = system_drive_warning(root)
        if warn:
            warnings.append(warn)
            log.warning(warn)
            _say(f"[warn] {warn}")
        log.info("investigation %s collect: host=%s modules=%s", __version__, hostname,
                 ",".join(c.meta.name for c in selected))

        preflight = run_preflight(selected, ctx, installer=None)
        preflight_dict = preflight.to_dict()

        approved: dict[str, bool] = {}
        for cls in selected:
            if cls.meta.confirm and cls.meta.name not in preflight.skipped:
                approved[cls.meta.name] = bool(confirm(cls.meta.confirm))

        for cls in selected:
            name = cls.meta.name
            if state["aborted"]:
                record(cls, "skipped", "aborted")
                continue
            if name in preflight.skipped:
                record(cls, "skipped", preflight.skipped[name])
                continue
            if cls.meta.confirm and not approved.get(name, False):
                record(cls, "declined", declined_detail)
                continue
            t0 = time.monotonic()
            _say(f"[{selected.index(cls) + 1}/{len(selected)}] {name} ...")
            try:
                result = cls().collect(ctx, root)
                detail = f"{result} rows" if isinstance(result, int) and not isinstance(result, bool) else ""
                detail = details.get(name) or detail
                record(cls, "ok", detail, time.monotonic() - t0)
            except KeyboardInterrupt:
                state["aborted"] = True
                record(cls, "skipped", "aborted", time.monotonic() - t0)
            except Exception as exc:
                record(cls, "error", f"{type(exc).__name__}: {exc}", time.monotonic() - t0)
    except KeyboardInterrupt as exc:
        state["aborted"] = True
        crash = exc
    except BaseException as exc:
        crash = exc
        warnings.append(f"collection crashed: {type(exc).__name__}: {exc}")
        log.exception("collection crashed")

    for cls in selected:
        if cls.meta.name not in records:
            records[cls.meta.name] = {"name": cls.meta.name, "category": cls.meta.category,
                                      "status": "skipped", "detail": "aborted", "seconds": 0.0}
    modules = [records[c.meta.name] for c in selected]
    all_ok = all(m["status"] == "ok" for m in modules)
    aborted = state["aborted"]
    forced = ctx.options.get("force_partial")
    if forced:
        all_ok = False
        log.warning("package marked partial: %s", forced)
    status = "aborted" if aborted else ("complete" if all_ok and crash is None else "partial")
    finished = now()
    local = finished.astimezone()
    info = {
        "tool_version": __version__,
        "case_id": case_id,
        "examiner": examiner,
        "hostname": hostname,
        "collector": collector_identity(),
        "started_utc": _iso(started),
        "finished_utc": _iso(finished),
        "local_timezone": local.tzname() or "",
        "utc_offset": local.strftime("%z"),
        "status": status,
        "modules": modules,
        "preflight": preflight_dict,
        "warnings": warnings,
    }
    manifest_path = write_manifest(root, info, extra_files)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    log.info("done: status=%s", status)
    if crash is not None:
        crash.package_root = root
        raise crash
    if aborted:
        stop = KeyboardInterrupt()
        stop.package_root = root
        raise stop
    return CollectResult(root=root, manifest=manifest, exit_code=0 if all_ok else 1)
