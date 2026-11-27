"""Module registration and discovery (built-in, user directory, entry points)."""

from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
import os
import pkgutil
import sys
import traceback
from pathlib import Path

from investigation.core.module import BaseModule, ModuleType
from investigation.core.frozen import is_frozen

ENTRY_POINT_GROUP = "investigation.modules"

_GLOBAL: list[type[BaseModule]] = []
_CAPTURE: list[list[type[BaseModule]]] = []


def register(cls: type[BaseModule]) -> type[BaseModule]:
    """Class decorator marking a module for discovery."""
    if not hasattr(cls, "meta"):
        raise TypeError(f"{cls.__name__} has no 'meta'")
    (_CAPTURE[-1] if _CAPTURE else _GLOBAL).append(cls)
    return cls


def investigation_home() -> Path:
    env = os.environ.get("INVESTIGATION_HOME")
    return Path(env) if env else Path.home() / ".investigation"


def user_modules_dir() -> Path:
    return investigation_home() / "modules"


class ModuleRegistry:
    def __init__(self, fresh: bool = False):
        self._modules: dict[str, type[BaseModule]] = {}
        self.load_errors: list[tuple[str, str]] = []
        if not fresh:
            for cls in _GLOBAL:
                self.add(cls)

    def add(self, cls: type[BaseModule]) -> None:
        name = cls.meta.name
        existing = self._modules.get(name)
        if existing is cls:
            return
        if existing is not None:
            raise ValueError(f"duplicate module name {name!r} ({existing.__module__} vs {cls.__module__})")
        self._modules[name] = cls

    def _add_reporting(self, origin: str, classes: list[type[BaseModule]]) -> None:
        for cls in classes:
            try:
                self.add(cls)
            except ValueError as exc:
                self.load_errors.append((origin, str(exc)))

    def discover(self, user_dir: Path | None = None, builtin: bool = True, entry_points: bool = True) -> None:
        if builtin:
            import investigation.modules as pkg

            if is_frozen():
                from investigation._builtin_modules import BUILTIN_MODULES as names
            else:
                names = [i.name for i in pkgutil.walk_packages(pkg.__path__, prefix=pkg.__name__ + ".")]
            for name in names:
                try:
                    importlib.import_module(name)
                except Exception as exc:
                    self.load_errors.append((name, f"{type(exc).__name__}: {exc}"))
            self._add_reporting("builtin", list(_GLOBAL))

        if user_dir is not None and Path(user_dir).is_dir():
            for path in sorted(Path(user_dir).glob("*.py")):
                self._load_file(path)

        if entry_points:
            for ep in importlib.metadata.entry_points(group=ENTRY_POINT_GROUP):
                captured: list[type[BaseModule]] = []
                _CAPTURE.append(captured)
                try:
                    obj = ep.load()
                    if isinstance(obj, type) and issubclass(obj, BaseModule) and obj not in captured:
                        captured.append(obj)
                except Exception as exc:
                    self.load_errors.append((f"entry point {ep.name}", f"{type(exc).__name__}: {exc}"))
                finally:
                    _CAPTURE.pop()
                self._add_reporting(f"entry point {ep.name}", captured)

    def _load_file(self, path: Path) -> None:
        mod_name = f"investigation_user_module_{path.stem}_{abs(hash(str(path.resolve())))}"
        captured: list[type[BaseModule]] = []
        _CAPTURE.append(captured)
        try:
            spec = importlib.util.spec_from_file_location(mod_name, path)
            assert spec and spec.loader
            module = importlib.util.module_from_spec(spec)
            sys.modules[mod_name] = module
            spec.loader.exec_module(module)
        except Exception as exc:
            sys.modules.pop(mod_name, None)
            last = traceback.format_exception_only(type(exc), exc)[-1].strip()
            self.load_errors.append((path.name, last))
            return
        finally:
            _CAPTURE.pop()
        self._add_reporting(path.name, captured)

    def get(self, name: str) -> type[BaseModule]:
        try:
            return self._modules[name]
        except KeyError:
            raise KeyError(f"unknown module {name!r}") from None

    def by_type(self, t: ModuleType) -> list[type[BaseModule]]:
        return sorted((c for c in self._modules.values() if c.meta.type is t), key=lambda c: c.meta.name)

    def all(self) -> list[type[BaseModule]]:
        return sorted(self._modules.values(), key=lambda c: (c.meta.type.value, c.meta.name))
