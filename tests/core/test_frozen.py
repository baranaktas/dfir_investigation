import pkgutil
import sys
from pathlib import Path

import investigation
import investigation.modules as modpkg
from investigation.core import frozen


def test_resource_frozen_and_source(monkeypatch, tmp_path):
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert not frozen.is_frozen()
    assert frozen.resource("profiles") == Path(investigation.__file__).parent / "profiles"
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    assert frozen.is_frozen()
    assert frozen.resource("profiles") == tmp_path / "investigation" / "profiles"
    assert frozen.resource("") == tmp_path / "investigation"


def test_builtin_module_list_in_sync():
    from investigation._builtin_modules import BUILTIN_MODULES

    found = sorted(i.name for i in pkgutil.walk_packages(modpkg.__path__, prefix=modpkg.__name__ + "."))
    assert sorted(BUILTIN_MODULES) == found


def test_profiles_load_via_resource():
    from investigation.core import profiles

    assert profiles.BUILTIN_DIR == frozen.resource("profiles")
    assert any(profiles.BUILTIN_DIR.glob("*.yaml"))


def test_volatility_command_frozen_and_source(monkeypatch):
    from investigation.modules.parsers import memory

    monkeypatch.setattr(memory, "VOL_COMMAND", None)
    monkeypatch.setattr(memory, "is_frozen", lambda: True)
    assert memory.VolatilityRunner("x.raw").command == [sys.executable, "__volatility__"]
    monkeypatch.setattr(memory, "is_frozen", lambda: False)
    cmd = memory.VolatilityRunner("x.raw").command
    assert cmd[:2] == [sys.executable, "-I"] and "volatility3.cli" in cmd[-1]


def test_entry_dispatches_volatility(monkeypatch):
    import importlib.util
    import volatility3.cli as vcli

    seen = []
    monkeypatch.setattr(vcli, "main", lambda: seen.append(list(sys.argv)) or 0)
    monkeypatch.setattr(sys, "argv", ["investigation.exe", "__volatility__", "-q"])
    spec = importlib.util.spec_from_file_location("entry", Path(__file__).resolve().parents[2] / "packaging" / "entry.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.run() == 0 and seen == [["investigation.exe", "-q"]]


def test_doctor_reports_dissect_plugins_when_frozen(monkeypatch, capsys):
    from investigation import cli

    monkeypatch.setattr(cli, "is_frozen", lambda: True)
    monkeypatch.setattr(cli, "_dissect_plugin_count", lambda: 0)
    assert cli._frozen_checks()[0] is False
    monkeypatch.setattr(cli, "_dissect_plugin_count", lambda: 12)
    ok, line = cli._frozen_checks()
    assert ok and "12" in line
    monkeypatch.setattr(cli, "is_frozen", lambda: False)
    assert cli._frozen_checks() is None


def test_jail_allows_the_frozen_exe_and_bundle(tmp_path, monkeypatch):
    import sys

    from investigation.modules.sources import target as target_mod

    bundle = tmp_path / "_MEI123"
    bundle.mkdir()
    exe = tmp_path / "dist" / "investigation.exe"
    exe.parent.mkdir()
    exe.write_bytes(b"MZ")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(bundle), raising=False)
    monkeypatch.setattr(sys, "executable", str(exe))
    allowed = target_mod._allowed_host_paths(evidence)
    assert allowed(exe.resolve())
    assert allowed((bundle / "dissect" / "target" / "plugins" / "x.py").resolve())
    assert not allowed((tmp_path / "dist" / "other.txt").resolve())
