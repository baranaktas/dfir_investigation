import pytest

from investigation.core.module import (
    DetectionModule,
    ModuleMeta,
    ModuleType,
    OutputModule,
    ParserModule,
    SourceModule,
)
from investigation.core.profiles import Profile, ProfileError, list_profiles, load_profile, resolve
from investigation.core.registry import ModuleRegistry

BASES = {
    ModuleType.SOURCE: SourceModule,
    ModuleType.PARSER: ParserModule,
    ModuleType.DETECTION: DetectionModule,
    ModuleType.OUTPUT: OutputModule,
}


def _mod(name, t, depends_on=()):
    cls = type(name, (BASES[t],), {})
    cls.meta = ModuleMeta(name=name, description="", type=t, depends_on=tuple(depends_on))
    return cls


@pytest.fixture
def reg():
    r = ModuleRegistry(fresh=True)
    for cls in [
        _mod("dir", ModuleType.SOURCE),
        _mod("p1", ModuleType.PARSER),
        _mod("p2", ModuleType.PARSER),
        _mod("rules", ModuleType.DETECTION),
        _mod("html", ModuleType.OUTPUT),
    ]:
        r.add(cls)
    return r


def names(mods):
    return [m.meta.name for m in mods]


def test_wildcard_expansion(reg):
    p = Profile("x", "", ["output:*", "parser:*", "source:*", "detection:*"], [])
    assert names(resolve(p, reg)) == ["dir", "p1", "p2", "rules", "html"]


def test_exclude(reg):
    p = Profile("x", "", ["parser:*"], ["p2"])
    assert names(resolve(p, reg)) == ["p1"]


def test_depends_on_pulled_in_and_ordered():
    r = ModuleRegistry(fresh=True)
    r.add(_mod("b", ModuleType.PARSER))
    r.add(_mod("a", ModuleType.PARSER, depends_on=["b"]))
    r.add(_mod("c", ModuleType.DETECTION, depends_on=["a"]))
    assert names(resolve(Profile("x", "", ["c"], []), r)) == ["b", "a", "c"]


def test_cycle_raises():
    r = ModuleRegistry(fresh=True)
    r.add(_mod("a", ModuleType.PARSER, depends_on=["b"]))
    r.add(_mod("b", ModuleType.PARSER, depends_on=["a"]))
    with pytest.raises(ProfileError, match="cycle"):
        resolve(Profile("x", "", ["a"], []), r)


def test_unknown_module_raises(reg):
    with pytest.raises(ProfileError, match="nope"):
        resolve(Profile("x", "", ["nope"], []), reg)
    with pytest.raises(ProfileError, match="bogus"):
        resolve(Profile("x", "", ["bogus:*"], []), reg)


def test_builtin_profiles_load(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path))
    full = load_profile("full")
    assert "parser:*" in full.modules
    assert {"full", "triage"} <= {p.name for p in list_profiles()}
    with pytest.raises(ProfileError):
        load_profile("does-not-exist")


def test_user_profile_overrides_and_path(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path))
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "mine.yaml").write_text("name: mine\ndescription: d\nmodules: [p1]\n")
    assert load_profile("mine").modules == ["p1"]
    f = tmp_path / "other.yaml"
    f.write_text("name: other\ndescription: d\nmodules: [p2]\nexclude: []\n")
    assert load_profile(str(f)).name == "other"
    assert "mine" in {p.name for p in list_profiles()}


def test_invalid_profile_yaml(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text("name: bad\nmodules: not-a-list\n")
    with pytest.raises(ProfileError):
        load_profile(str(f))
