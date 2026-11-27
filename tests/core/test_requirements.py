import platform
import shutil
import sys
from collections import namedtuple

from investigation.core.requirements import (
    AdminRights,
    Context,
    ExternalTool,
    FreeSpace,
    Platform,
    PythonPackage,
    PythonVersion,
    Status,
)

CTX = Context()


def test_python_package_ok():
    r = PythonPackage("pyyaml", "yaml").check(CTX)
    assert r.status is Status.OK
    assert r.mandatory


def test_python_package_missing_has_fix():
    r = PythonPackage("nonexistent-pkg-xyz", "nonexistent_pkg_xyz").check(CTX)
    assert r.status is Status.MISSING
    assert "pip install nonexistent-pkg-xyz" in r.fix


def test_python_package_too_old():
    r = PythonPackage("pyyaml", "yaml", min_version="999.0").check(CTX)
    assert r.status is Status.MISSING
    assert "999.0" in r.detail


def test_external_tool():
    assert ExternalTool("python", ("python3",)).check(CTX).status is Status.OK
    assert ExternalTool("nope", ("definitely-not-a-tool",)).check(CTX).status is Status.MISSING


def test_platform_mismatch(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    assert Platform(("windows",)).check(CTX).status is Status.MISSING
    assert Platform(("windows", "linux")).check(CTX).status is Status.OK


def test_free_space_warns(monkeypatch, tmp_path):
    Usage = namedtuple("Usage", "total used free")
    monkeypatch.setattr(shutil, "disk_usage", lambda p: Usage(100, 90, 10))
    r = FreeSpace(100, mandatory=False).check(Context(output_dir=tmp_path / "not" / "yet"))
    assert r.status is Status.WARN
    r = FreeSpace(100, mandatory=True).check(Context(output_dir=tmp_path))
    assert r.status is Status.MISSING
    assert FreeSpace(5).check(Context(output_dir=tmp_path)).status is Status.OK


def test_python_version_rejects_314(monkeypatch):
    monkeypatch.setattr(sys, "version_info", (3, 14, 0))
    r = PythonVersion().check(CTX)
    assert r.status is Status.MISSING
    assert "3.14" in r.detail


def test_python_version_current_ok():
    assert PythonVersion().check(CTX).status is Status.OK


def test_admin_rights_returns_result():
    r = AdminRights().check(CTX)
    assert r.status in (Status.OK, Status.MISSING)
    assert r.requirement


def test_python_version_rejects_311(monkeypatch):
    monkeypatch.setattr(sys, "version_info", (3, 11, 9))
    r = PythonVersion().check(CTX)
    assert r.status is Status.MISSING
    assert "too old" in r.detail
