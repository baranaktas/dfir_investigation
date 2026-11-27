import sys

from investigation.core.module import ModuleMeta, ModuleType, ParserModule
from investigation.core.preflight import run_preflight
from investigation.core.requirements import (
    CheckResult,
    Context,
    ExternalTool,
    PythonPackage,
    Requirement,
    Status,
)


def _mod(name, requirements=(), depends_on=()):
    cls = type(name, (ParserModule,), {})
    cls.meta = ModuleMeta(
        name=name, description="", type=ModuleType.PARSER,
        requirements=tuple(requirements), depends_on=tuple(depends_on),
    )
    return cls


class FlipPackage(PythonPackage):
    """Missing until `installed` is set (simulates pip install)."""

    def __init__(self, state):
        super().__init__("fake-dist", "fake_dist")
        self.state = state

    def check(self, ctx):
        if self.state["installed"]:
            return self._result(Status.OK, "fake-dist 1.0")
        return self._fail("fake-dist is not installed", "pip install fake-dist")


def names(mods):
    return [m.meta.name for m in mods]


def test_framework_checks_present():
    rep = run_preflight([], Context())
    assert "framework" in rep.results
    assert rep.results["framework"][0].status is Status.OK


def test_missing_mandatory_skips_module():
    bad = _mod("bad", [ExternalTool("x", ("definitely-not-a-tool",))])
    good = _mod("good")
    rep = run_preflight([bad, good], Context(allow_install=False))
    assert names(rep.runnable) == ["good"]
    assert "definitely-not-a-tool" in rep.skipped["bad"]
    assert not rep.ok


def test_optional_missing_does_not_skip():
    m = _mod("m", [ExternalTool("x", ("definitely-not-a-tool",), mandatory=False)])
    rep = run_preflight([m], Context())
    assert names(rep.runnable) == ["m"]
    assert rep.results["m"][0].status is Status.WARN
    assert rep.ok


def test_installer_called_once_and_rechecked():
    state = {"installed": False}
    calls = []

    def installer(dists):
        calls.append(list(dists))
        state["installed"] = True
        return True

    m1 = _mod("m1", [FlipPackage(state)])
    m2 = _mod("m2", [FlipPackage(state)])
    rep = run_preflight([m1, m2], Context(), installer=installer)
    assert calls == [["fake-dist"]]
    assert names(rep.runnable) == ["m1", "m2"]
    assert rep.installed == ["fake-dist"]
    assert rep.results["m1"][0].status is Status.OK


def test_no_install_when_disallowed():
    state = {"installed": False}
    calls = []
    m = _mod("m", [FlipPackage(state)])
    rep = run_preflight([m], Context(allow_install=False), installer=lambda d: calls.append(d) or True)
    assert calls == []
    assert "m" in rep.skipped


def test_no_install_when_frozen(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    state = {"installed": False}
    calls = []
    m = _mod("m", [FlipPackage(state)])
    rep = run_preflight([m], Context(), installer=lambda d: calls.append(d) or True)
    assert calls == []
    assert "m" in rep.skipped


def test_dependent_of_skipped_is_skipped():
    a = _mod("a", [ExternalTool("x", ("definitely-not-a-tool",))])
    b = _mod("b", depends_on=["a"])
    c = _mod("c", depends_on=["b"])
    rep = run_preflight([a, b, c], Context(allow_install=False))
    assert rep.runnable == []
    assert rep.skipped["b"] == "depends on skipped module a"
    assert rep.skipped["c"] == "depends on skipped module b"


class Exploding(Requirement):
    def describe(self):
        return "exploding"

    def check(self, ctx):
        raise RuntimeError("kaboom")


def test_crashing_check_counts_as_missing():
    rep = run_preflight([_mod("m", [Exploding()])], Context())
    assert "m" in rep.skipped
    assert "kaboom" in rep.skipped["m"]


def test_to_dict_serializable():
    import json

    rep = run_preflight([_mod("m")], Context())
    json.dumps(rep.to_dict())
