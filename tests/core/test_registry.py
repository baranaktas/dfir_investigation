import pytest

from investigation.core.module import ModuleMeta, ModuleType, ParserModule
from investigation.core.registry import ModuleRegistry, register, user_modules_dir
from investigation.core.requirements import AdminRights, Platform, PythonPackage


def _parser(name, **meta):
    cls = type(name, (ParserModule,), {"parse": lambda self, s, c, e: iter(())})
    cls.meta = ModuleMeta(name=name, description="d", type=ModuleType.PARSER, **meta)
    return cls


def test_register_and_get():
    reg = ModuleRegistry(fresh=True)
    cls = _parser("dummy_a")
    reg.add(cls)
    assert reg.get("dummy_a") is cls
    assert reg.by_type(ModuleType.PARSER) == [cls]
    with pytest.raises(KeyError):
        reg.get("missing")


def test_duplicate_name_rejected():
    reg = ModuleRegistry(fresh=True)
    reg.add(_parser("dup"))
    with pytest.raises(ValueError):
        reg.add(_parser("dup"))


def test_discover_user_dir(tmp_path):
    (tmp_path / "hello.py").write_text(
        "from investigation.core.module import ModuleMeta, ModuleType, ParserModule\n"
        "from investigation.core.registry import register\n"
        "@register\n"
        "class Hello(ParserModule):\n"
        "    meta = ModuleMeta(name='hello_parser', description='hi', type=ModuleType.PARSER)\n"
        "    def parse(self, source, ctx, errors):\n"
        "        return iter(())\n"
    )
    reg = ModuleRegistry(fresh=True)
    reg.discover(user_dir=tmp_path, builtin=False)
    assert reg.get("hello_parser").meta.description == "hi"
    assert reg.load_errors == []


def test_broken_user_module_is_reported(tmp_path):
    (tmp_path / "bad.py").write_text("raise RuntimeError('boom')\n")
    reg = ModuleRegistry(fresh=True)
    reg.discover(user_dir=tmp_path, builtin=False)
    assert len(reg.load_errors) == 1
    name, msg = reg.load_errors[0]
    assert name == "bad.py"
    assert "boom" in msg


def test_discover_builtin_twice_is_idempotent():
    reg = ModuleRegistry()
    reg.discover(user_dir=None)
    reg.discover(user_dir=None)
    assert reg.load_errors == []


def test_all_requirements_adds_platform_and_admin():
    cls = _parser("req", platforms=("windows",), requires_admin=True, requirements=(PythonPackage("pyyaml", "yaml"),))
    reqs = cls.all_requirements()
    assert any(isinstance(r, PythonPackage) for r in reqs)
    assert any(isinstance(r, Platform) for r in reqs)
    assert any(isinstance(r, AdminRights) for r in reqs)
    assert _parser("plain").all_requirements() == []


def test_user_modules_dir_env(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path))
    assert user_modules_dir() == tmp_path / "modules"
    monkeypatch.delenv("INVESTIGATION_HOME")
    assert user_modules_dir().name == "modules"
    assert user_modules_dir().parent.name == ".investigation"
