"""The analysis pipeline: source -> parsers -> event store -> detections -> outputs."""

from __future__ import annotations

import logging
import os
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from investigation import __version__
from investigation.core.models import Finding
from investigation.core.module import ModuleType
from investigation.core.package import ManifestError
from investigation.core.artefacts import load_collector, mark
from investigation.core.console import Throttle, say as _say
from investigation.core.frozen import is_frozen
from investigation.core.preflight import pip_installer, run_preflight
from investigation.core.profiles import Profile, load_profile, resolve
from investigation.core.registry import ModuleRegistry, user_modules_dir
from investigation.core.requirements import Context
from investigation.core.result import AnalysisResult
from investigation.core.store import EventStore

log = logging.getLogger("investigation")

SUB_SOURCE_SKIP = {"live", "memory", "yara"}

DB_NAME = "investigation.db"
LOG_NAME = "investigation.log"


class InputError(Exception):
    pass


class OutputDirError(Exception):
    pass


def default_registry() -> ModuleRegistry:
    reg = ModuleRegistry()
    reg.discover(user_dir=user_modules_dir())
    return reg


def _inside(out: Path, inp: Path) -> bool:
    """True if `out` is `inp` or below it. Compares device/inode of every existing ancestor, so
    case-insensitive filesystems, symlinks and bind mounts cannot sneak the output into the evidence."""
    if out == inp or out.is_relative_to(inp):
        return True
    for ancestor in (out, *out.parents):
        if ancestor.exists():
            try:
                if os.path.samefile(ancestor, inp):
                    return True
            except OSError:
                continue
    return False


def _check_paths(input_path: Path, out_dir: Path, force: bool) -> None:
    if not input_path.exists():
        raise InputError(f"input does not exist: {input_path}")
    inp, out = input_path.resolve(), out_dir.resolve()
    if inp.is_dir() and _inside(out, inp):
        raise OutputDirError(f"output directory {out} is inside the evidence {inp}; evidence must stay read-only")
    if out.exists() and not out.is_dir():
        raise OutputDirError(f"output path exists and is not a directory: {out}")
    if out.is_dir() and any(out.iterdir()) and not force:
        raise OutputDirError(f"output directory {out} is not empty; use --force to overwrite")


def _counted(events, name: str):
    """Pass events through, printing a running count every couple of seconds for big parsers."""
    throttle = Throttle()
    throttle.ready()
    count = 0
    for event in events:
        count += 1
        if throttle.ready():
            _say(f"  {name}: {count} events")
        yield event


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def analyze(
    input_path: Path,
    out_dir: Path,
    profile: str | Profile = "full",
    case_id: str = "",
    examiner: str = "",
    allow_install: bool = True,
    force: bool = False,
    registry: ModuleRegistry | None = None,
    options: dict | None = None,
) -> AnalysisResult:
    input_path, out_dir = Path(input_path), Path(out_dir)
    _check_paths(input_path, out_dir, force)
    started = _now()

    reg = registry if registry is not None else default_registry()
    prof = profile if isinstance(profile, Profile) else load_profile(profile)
    modules = resolve(prof, reg)

    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in (DB_NAME, LOG_NAME):
        (out_dir / stale).unlink(missing_ok=True)
    handler = logging.FileHandler(out_dir / LOG_NAME, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    try:
        return _run(input_path, out_dir, prof, modules, reg, case_id, examiner, allow_install, started,
                    dict(options or {}))
    finally:
        log.removeHandler(handler)
        handler.close()


def _run(input_path, out_dir, prof, modules, reg, case_id, examiner, allow_install, started,
         options) -> AnalysisResult:
    allow_install = allow_install and not is_frozen()
    ctx = Context(output_dir=out_dir, input_path=input_path, allow_install=allow_install, options=options)
    log.info("investigation %s: input=%s profile=%s", __version__, input_path, prof.name)
    for origin, msg in reg.load_errors:
        log.warning("module load error %s: %s", origin, msg)

    preflight = run_preflight(modules, ctx, installer=pip_installer if allow_install else None)
    for name, why in preflight.skipped.items():
        log.warning("skipping module %s: %s", name, why)
    runnable = preflight.runnable

    module_errors: list[tuple[str, str]] = [(f"load:{o}", m) for o, m in reg.load_errors]
    modules_run: list[str] = []

    def errors(module: str, message: str) -> None:
        log.warning("%s: %s", module, message)
        module_errors.append((module, message))

    source = None
    open_failures: list[str] = []
    sources = sorted((m for m in runnable if m.meta.type is ModuleType.SOURCE),
                     key=lambda m: (m.meta.priority, m.meta.name))
    for cls in sources:
        try:
            mod = cls()
            if mod.can_open(input_path):
                source = mod.open(input_path)
                modules_run.append(cls.meta.name)
                log.info("opened input with source module %s", cls.meta.name)
                break
        except ManifestError as exc:
            raise InputError(str(exc)) from None
        except Exception as exc:
            errors(cls.meta.name, f"{type(exc).__name__}: {exc}")
            open_failures.append(f"{cls.meta.name}: {exc}")
    if source is None:
        reason = f" ({'; '.join(open_failures)})" if open_failures else ""
        raise InputError(f"unsupported input (no source module can open it): {input_path}{reason}")

    try:
        system_info = {str(k): str(v) for k, v in source.system_info().items()}
    except Exception as exc:
        errors(modules_run[0], f"system info failed: {type(exc).__name__}: {exc}")
        system_info = {}

    collector = load_collector(input_path)
    store = EventStore(out_dir / DB_NAME)
    findings: list[Finding] = []
    try:
        parsers = [m for m in runnable if m.meta.type is ModuleType.PARSER]
        detections = [m for m in runnable if m.meta.type is ModuleType.DETECTION]
        steps = len(parsers) + len(detections)
        for number, cls in enumerate(parsers, 1):
            log.info("running parser %s", cls.meta.name)
            modules_run.append(cls.meta.name)
            _say(f"[{number}/{steps}] parsing {cls.meta.name}")
            try:
                n = store.add_many(mark(_counted(cls().parse(source, ctx, errors), cls.meta.name), collector))
                _say(f"  {cls.meta.name}: {n} events")
                log.info("parser %s produced %d events", cls.meta.name, n)
            except Exception as exc:
                errors(cls.meta.name, f"crashed: {type(exc).__name__}: {exc}")

        try:
            subs = source.sub_sources()
        except Exception as exc:
            errors(modules_run[0], f"cannot list sub-sources: {type(exc).__name__}: {exc}")
            subs = []
        for prefix, sub in subs:
            _say(f"parsing shadow copy {prefix}")
            for cls in [m for m in runnable if m.meta.type is ModuleType.PARSER]:
                spec = getattr(cls, "spec", None)
                if cls.meta.name in SUB_SOURCE_SKIP or getattr(spec, "heavy", False):
                    continue
                label = f"{cls.meta.name}@{prefix}"
                try:
                    events = (replace(e, source_file=f"{prefix}:{e.source_file}", tags=tuple(e.tags) + ("vss",))
                              for e in cls().parse(sub, ctx, lambda m, msg, label=label: errors(label, msg)))
                    store.add_many(mark(events, collector))
                except Exception as exc:
                    errors(label, f"crashed: {type(exc).__name__}: {exc}")

        for number, cls in enumerate(detections, len(parsers) + 1):
            log.info("running detection %s", cls.meta.name)
            modules_run.append(cls.meta.name)
            _say(f"[{number}/{steps}] detecting {cls.meta.name}")
            try:
                found = list(cls().detect(store, ctx, errors))
                findings.extend(found)
                log.info("detection %s produced %d findings", cls.meta.name, len(found))
            except Exception as exc:
                errors(cls.meta.name, f"crashed: {type(exc).__name__}: {exc}")
    finally:
        source_name = modules_run[0] if modules_run else "source"
        for msg in source.access_errors():
            errors(source_name, msg)
        source.close()

    result = AnalysisResult(
        case={
            "input": str(input_path.resolve()),
            "case_id": case_id,
            "examiner": examiner,
            "profile": prof.name,
            "started_utc": started,
            "finished_utc": "",
            "tool_version": __version__,
            "system": system_info,
        },
        store=store,
        findings=findings,
        preflight=preflight,
        module_errors=module_errors,
        modules_run=modules_run,
        collector=collector,
    )

    if "sigma" in modules_run:
        from investigation.modules.detections.sigma import SigmaDetection

        result_sigma = dict(SigmaDetection.last_stats)
    else:
        result_sigma = None

    try:
        from investigation.core.story import build_stories, notes_for

        result.notes = notes_for(store.artifact_counts())
        result.stories = build_stories(store, findings)
    except Exception as exc:
        errors("story", f"crashed: {type(exc).__name__}: {exc}")

    if result_sigma is not None:
        result.case["sigma"] = result_sigma

    outputs = [m for m in runnable if m.meta.type is ModuleType.OUTPUT]
    if outputs:
        _say("writing report ...")
    result.modules_run.extend(m.meta.name for m in outputs)
    result.case["finished_utc"] = _now()
    for cls in outputs:
        try:
            cls().write(result, out_dir, ctx)
        except Exception as exc:
            errors(cls.meta.name, f"crashed: {type(exc).__name__}: {exc}")
    log.info("done: %d events, %d findings, %d module errors", store.count(), len(findings), len(module_errors))
    store.close()
    return result
