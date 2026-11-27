"""YAML profiles: named module selections with dependency resolution."""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from investigation.core.module import BaseModule, ModuleType
from investigation.core.registry import ModuleRegistry, investigation_home
from investigation.core.frozen import resource

BUILTIN_DIR = resource("profiles")
TYPE_ORDER = [ModuleType.COLLECTOR, ModuleType.SOURCE, ModuleType.PARSER, ModuleType.DETECTION, ModuleType.OUTPUT]


class ProfileError(Exception):
    pass


@dataclass
class Profile:
    name: str
    description: str
    modules: list[str]
    exclude: list[str] = field(default_factory=list)


def user_profiles_dir() -> Path:
    return investigation_home() / "profiles"


def _parse(path: Path) -> Profile:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ProfileError(f"cannot read profile {path}: {exc}") from None
    if not isinstance(data, dict):
        raise ProfileError(f"profile {path} must be a mapping")
    modules = data.get("modules")
    exclude = data.get("exclude") or []
    if not isinstance(modules, list) or not all(isinstance(m, str) for m in modules):
        raise ProfileError(f"profile {path}: 'modules' must be a list of strings")
    if not isinstance(exclude, list) or not all(isinstance(m, str) for m in exclude):
        raise ProfileError(f"profile {path}: 'exclude' must be a list of strings")
    return Profile(
        name=str(data.get("name") or path.stem),
        description=str(data.get("description") or ""),
        modules=modules,
        exclude=exclude,
    )


def load_profile(name_or_path: str) -> Profile:
    p = Path(name_or_path)
    if p.suffix in (".yaml", ".yml") and p.is_file():
        return _parse(p)
    for d in (user_profiles_dir(), BUILTIN_DIR):
        for ext in (".yaml", ".yml"):
            candidate = d / f"{name_or_path}{ext}"
            if candidate.is_file():
                return _parse(candidate)
    raise ProfileError(f"unknown profile {name_or_path!r}")


def list_profiles() -> list[Profile]:
    found: dict[str, Profile] = {}
    for d in (BUILTIN_DIR, user_profiles_dir()):
        if d.is_dir():
            for f in sorted(d.glob("*.y*ml")):
                try:
                    prof = _parse(f)
                except ProfileError:
                    continue
                found[prof.name] = prof
    return sorted(found.values(), key=lambda p: p.name)


def _expand(item: str, registry: ModuleRegistry) -> list[type[BaseModule]]:
    if item.endswith(":*"):
        tname = item[:-2]
        try:
            t = ModuleType(tname)
        except ValueError:
            raise ProfileError(f"unknown module type {tname!r} in {item!r}") from None
        return registry.by_type(t)
    try:
        return [registry.get(item)]
    except KeyError:
        raise ProfileError(f"unknown module {item!r}") from None


def resolve(profile: Profile, registry: ModuleRegistry) -> list[type[BaseModule]]:
    excluded = set(profile.exclude)
    selected: dict[str, type[BaseModule]] = {}
    for item in profile.modules:
        for cls in _expand(item, registry):
            if cls.meta.name not in excluded:
                selected[cls.meta.name] = cls

    stack = list(selected.values())
    while stack:
        cls = stack.pop()
        for dep in cls.meta.depends_on:
            if dep not in selected:
                try:
                    selected[dep] = registry.get(dep)
                except KeyError:
                    raise ProfileError(f"module {cls.meta.name!r} depends on unknown module {dep!r}") from None
                stack.append(selected[dep])

    def key(c: type[BaseModule]) -> tuple[int, str]:
        return (TYPE_ORDER.index(c.meta.type), c.meta.name)

    indegree = {n: 0 for n in selected}
    dependents: dict[str, list[str]] = {n: [] for n in selected}
    for n, c in selected.items():
        for dep in c.meta.depends_on:
            indegree[n] += 1
            dependents[dep].append(n)
    heap = [(key(selected[n]), n) for n, d in indegree.items() if d == 0]
    heapq.heapify(heap)
    order: list[type[BaseModule]] = []
    while heap:
        _, n = heapq.heappop(heap)
        order.append(selected[n])
        for m in dependents[n]:
            indegree[m] -= 1
            if indegree[m] == 0:
                heapq.heappush(heap, (key(selected[m]), m))
    if len(order) != len(selected):
        stuck = sorted(n for n, d in indegree.items() if d > 0)
        raise ProfileError(f"dependency cycle between modules: {', '.join(stuck)}")
    return order
