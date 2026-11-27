import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from investigation.core import collect as collect_mod
from investigation.core.collect import collect, package_dir_name
from investigation.core.module import CollectorModule, ModuleMeta, ModuleType
from investigation.core.registry import ModuleRegistry
from investigation.modules.collectors.base import VolatileCollector


def _meta(name, category="live", priority=100, confirm=""):
    return ModuleMeta(name=name, description=name, type=ModuleType.COLLECTOR, platforms=("any",),
                      category=category, priority=priority, confirm=confirm)


def _vol(name, **kw):
    class C(VolatileCollector):
        meta = _meta(name, **kw)
        filename = f"{name}.csv"
        columns = ("v",)

        def rows(self, ctx):
            return [{"v": name}]

    return C


def _reg(*classes):
    reg = ModuleRegistry(fresh=True)
    for c in classes:
        reg.add(c)
    return reg


def _status(res):
    return {m["name"]: m["status"] for m in res.manifest["modules"]}


def test_runs_in_priority_order_and_isolates_errors(tmp_path):
    class Boom(CollectorModule):
        meta = _meta("boom", priority=20)

        def collect(self, ctx, out_dir):
            raise RuntimeError("bad")

    res = collect(None, out=tmp_path, registry=_reg(_vol("zeta", priority=30), Boom, _vol("alpha", priority=10)))
    assert [m["name"] for m in res.manifest["modules"]] == ["alpha", "boom", "zeta"]
    assert _status(res) == {"alpha": "ok", "boom": "error", "zeta": "ok"}
    assert res.exit_code == 1 and res.manifest["status"] == "partial"
    assert (res.root / "volatile" / "zeta.csv").exists()
    assert (res.root / "collection.log").exists()


def test_selection_by_category_and_name(tmp_path):
    reg = _reg(_vol("a", category="live"), _vol("b", category="files"), _vol("c", category="memory"))
    assert set(_status(collect(None, out=tmp_path / "1", registry=reg))) == {"a", "b"}
    assert set(_status(collect(["files"], out=tmp_path / "2", registry=reg))) == {"b"}
    res = collect(["c"], out=tmp_path / "3", registry=reg)
    assert set(_status(res)) == {"c"} and res.exit_code == 0 and res.manifest["status"] == "complete"
    with pytest.raises(KeyError):
        collect(["nope"], out=tmp_path / "4", registry=reg)


def test_confirm_declined_skips_module(tmp_path):
    reg = _reg(_vol("risky", confirm="Really?"), _vol("safe"))
    asked = []
    res = collect(None, out=tmp_path, registry=reg, confirm=lambda t: asked.append(t) or False)
    assert asked == ["Really?"]
    assert _status(res) == {"risky": "declined", "safe": "ok"}
    assert not (res.root / "volatile" / "risky.csv").exists()
    res2 = collect(None, out=tmp_path / "y", registry=reg, confirm=lambda t: True)
    assert _status(res2)["risky"] == "ok"


def test_keyboard_interrupt_writes_aborted_manifest(tmp_path):
    class Stop(CollectorModule):
        meta = _meta("stop", priority=20)

        def collect(self, ctx, out_dir):
            raise KeyboardInterrupt

    reg = _reg(_vol("first", priority=10), Stop, _vol("last", priority=30))
    with pytest.raises(KeyboardInterrupt) as stopped:
        collect(None, out=tmp_path, registry=reg)
    (root,) = list(tmp_path.iterdir())
    assert stopped.value.package_root == root
    import json

    m = json.loads((root / "manifest.json").read_text())
    assert m["status"] == "aborted"
    assert "volatile/first.csv" in [f["path"] for f in m["files"]]
    assert not (root / "volatile" / "last.csv").exists()


def test_package_dir_name():
    when = datetime(2026, 11, 26, 10, 30, tzinfo=timezone.utc)
    assert package_dir_name("WS 01/x", when) == "INV_WS_01_x_20261126T103000Z"


def test_no_process_spawning_in_collector_code():
    root = Path(collect_mod.__file__).resolve().parents[1]
    files = [root / "core" / "collect.py", *(root / "modules" / "collectors").rglob("*.py")]
    pattern = re.compile(r"subprocess|os\.system|os\.popen")
    for f in files:
        if f.name == "memory.py" and f.parent.name == "collectors":
            text = f.read_text(encoding="utf-8")
            assert not re.search(r"os\.system|os\.popen|shell\s*=\s*True|subprocess\.(?!Popen\b|PIPE\b|STDOUT\b|TimeoutExpired\b)\w+|from\s+subprocess|import\s+subprocess\s+as|__import__", text), f
            continue
        assert not pattern.search(f.read_text(encoding="utf-8")), f


def test_console_encoding_failure_does_not_kill_run(tmp_path, monkeypatch):
    import io
    import json
    import sys

    class Boom(CollectorModule):
        meta = _meta("boom")

        def collect(self, ctx, out_dir):
            raise RuntimeError("İstanbul Ωmega")

    stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
    monkeypatch.setattr(sys, "stdout", stream)
    res = collect(None, out=tmp_path, registry=_reg(Boom))
    assert _status(res) == {"boom": "error"}
    assert json.loads((res.root / "manifest.json").read_text(encoding="utf-8"))["status"] == "partial"


def test_interrupt_in_preflight_still_writes_manifest(tmp_path, monkeypatch):
    import json

    def boom(*a, **k):
        raise KeyboardInterrupt

    monkeypatch.setattr(collect_mod, "run_preflight", boom)
    with pytest.raises(KeyboardInterrupt):
        collect(None, out=tmp_path, registry=_reg(_vol("a")))
    (root,) = list(tmp_path.iterdir())
    m = json.loads((root / "manifest.json").read_text())
    assert m["status"] == "aborted"
    assert [x["status"] for x in m["modules"]] == ["skipped"]


def test_unexpected_crash_still_writes_manifest(tmp_path, monkeypatch):
    import json

    def boom(*a, **k):
        raise ValueError("x")

    monkeypatch.setattr(collect_mod, "run_preflight", boom)
    with pytest.raises(ValueError):
        collect(None, out=tmp_path, registry=_reg(_vol("a")))
    (root,) = list(tmp_path.iterdir())
    assert json.loads((root / "manifest.json").read_text())["status"] == "partial"


def test_volatile_collector_defaults_to_live_category(tmp_path):
    class V(VolatileCollector):
        meta = ModuleMeta(name="v", description="v", type=ModuleType.COLLECTOR)
        filename = "v.csv"
        columns = ("a",)

        def rows(self, ctx):
            return [{"a": 1}]

    assert V.meta.category == "live"
    res = collect(None, out=tmp_path, registry=_reg(V))
    assert _status(res) == {"v": "ok"}


def test_builtin_discovery_scans_collectors_package(tmp_path):
    import sys

    pkg = Path(collect_mod.__file__).resolve().parents[1] / "modules" / "collectors"
    mod = pkg / "_tmp_discovery_probe.py"
    mod.write_text(
        "from investigation.core.module import ModuleMeta, ModuleType\n"
        "from investigation.core.registry import register\n"
        "from investigation.modules.collectors.base import VolatileCollector\n"
        "@register\nclass Probe(VolatileCollector):\n"
        "    meta = ModuleMeta(name='discovery_probe', description='p', type=ModuleType.COLLECTOR)\n"
        "    filename='p.csv'\n    columns=('a',)\n"
    )
    try:
        reg = ModuleRegistry(fresh=True)
        reg.discover(user_dir=None, entry_points=False)
        assert reg.get("discovery_probe").meta.category == "live"
    finally:
        mod.unlink()
        sys.modules.pop("investigation.modules.collectors._tmp_discovery_probe", None)
        from investigation.core import registry as r
        r._GLOBAL[:] = [c for c in r._GLOBAL if c.meta.name != "discovery_probe"]
