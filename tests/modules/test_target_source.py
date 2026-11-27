import json
from pathlib import Path

import pytest

from investigation.core.pipeline import analyze
from investigation.modules.sources import target as target_mod
from investigation.modules.sources.target import TargetEvidence, TargetSource
from tests.helpers.windows_tree import FIXTURES, build_windows_tree, open_virtual_target

EVTX = Path(__file__).resolve().parent.parent / "fixtures" / "evtx"


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("INVESTIGATION_HOME", str(tmp_path / "home"))


@pytest.fixture
def tree(tmp_path):
    return build_windows_tree(tmp_path / "C")


def test_can_open(tree, tmp_path):
    src = TargetSource()
    assert src.can_open(tree)
    assert not src.can_open(EVTX)
    assert src.can_open(FIXTURES / "small.E01")
    (tmp_path / "notes.txt").write_text("x")
    assert not src.can_open(tmp_path / "notes.txt")
    kape = tmp_path / "kape"
    (kape / "C" / "Windows" / "System32").mkdir(parents=True)
    assert src.can_open(kape)


def test_target_evidence_glob_and_open(tree):
    ev = TargetEvidence(open_virtual_target(tree))
    assert ev.is_system
    found = list(ev.glob("windows/prefetch/*.pf"))
    assert [p.casefold() for p in found] == ["windows/prefetch/mpcmdrun.exe-962e6200.pf"]
    with ev.open(found[0]) as fh:
        assert fh.read(4) in (b"MAM\x04", b"\x1e\x00\x00\x00", b"\x17\x00\x00\x00")
    logs = list(ev.glob("windows/system32/winevt/logs/*.evtx"))
    assert len(logs) == 1


def test_system_info(tree):
    info = TargetEvidence(open_virtual_target(tree)).system_info()
    assert info["hostname"] == "DESKTOP-M3OSHQU"
    assert info["os"] == "windows"
    assert all(isinstance(v, str) for v in info.values())


def test_pipeline_picks_target_for_windows_tree(tree, tmp_path, monkeypatch):
    monkeypatch.setattr(target_mod, "open_target", open_virtual_target)
    before = {p: p.stat().st_mtime_ns for p in tree.rglob("*")}
    result = analyze(tree, tmp_path / "out", allow_install=False)
    assert result.modules_run[0] == "target"
    data = json.loads((tmp_path / "out" / "findings.json").read_text())
    assert data["case"]["system"]["hostname"] == "DESKTOP-M3OSHQU"
    assert result.store.artifact_counts().get("evtx", 0) > 0
    assert {p: p.stat().st_mtime_ns for p in tree.rglob("*")} == before


def test_e01_opens():
    ev = TargetSource().open(FIXTURES / "small.E01")
    assert ev.is_system is False
    list(ev.iter_files())


def test_directory_with_escaping_symlink_refused(tree, tmp_path):
    secret = tmp_path / "host_secret.txt"
    secret.write_text("analyst's private file")
    (tree / "Windows" / "Prefetch" / "LEAK.EXE-00000000.pf").symlink_to(secret)
    with pytest.raises(ValueError, match="symlink"):
        TargetSource().open(tree)


def test_directory_with_internal_symlink_allowed(tree, tmp_path, monkeypatch):
    monkeypatch.setattr(target_mod, "open_target", open_virtual_target)
    (tree / "Windows" / "link_to_prefetch").symlink_to(tree / "Windows" / "Prefetch")
    TargetSource().open(tree)


def test_vmx_and_ova_not_opened(tmp_path):
    for name in ("vm.vmx", "vm.ova"):
        (tmp_path / name).write_text('scsi0:0.fileName = "/etc/passwd"\n')
        assert not TargetSource().can_open(tmp_path / name)


def test_vmdk_descriptor_with_outside_extent_refused(tmp_path):
    d = tmp_path / "vm.vmdk"
    d.write_text('# Disk DescriptorFile\nversion=1\nRW 2048 FLAT "/etc/passwd" 0\n')
    with pytest.raises(ValueError, match="outside"):
        TargetSource().open(d)
    d.write_text('# Disk DescriptorFile\nversion=1\nRW 2048 FLAT "../elsewhere/disk-flat.vmdk" 0\n')
    with pytest.raises(ValueError, match="outside"):
        TargetSource().open(d)


def test_pipeline_falls_back_safely_on_refusal(tree, tmp_path):
    secret = tmp_path / "host_secret.evtx"
    secret.write_text("ANALYST-PRIVATE-CONTENT")
    (tree / "Windows" / "evil.evtx").symlink_to(secret)
    result = analyze(tree, tmp_path / "out", allow_install=False)
    assert result.modules_run[0] == "directory"
    assert any(m == "target" and "symlink" in msg for m, msg in result.module_errors)
    for f in (tmp_path / "out").iterdir():
        if f.suffix in (".html", ".csv", ".jsonl", ".json"):
            assert "ANALYST-PRIVATE-CONTENT" not in f.read_text(errors="ignore")


def test_unsupported_input_error_includes_reason(tmp_path):
    from investigation.core.pipeline import InputError

    d = tmp_path / "vm.vmdk"
    d.write_text('# Disk DescriptorFile\nRW 2048 FLAT "/etc/passwd" 0\n')
    with pytest.raises(InputError, match="outside the evidence"):
        analyze(d, tmp_path / "out", allow_install=False)


import struct

DESCRIPTOR_OUT = b'# Disk DescriptorFile\nversion=1\nRW 2048 FLAT "/etc/passwd" 0\n'


def test_descriptor_detected_by_content_not_name(tmp_path):
    d = tmp_path / "disk.dd"
    d.write_bytes(DESCRIPTOR_OUT)
    with pytest.raises(ValueError, match="outside"):
        TargetSource().open(d)


def test_oversized_descriptor_fails_closed(tmp_path):
    d = tmp_path / "big.img"
    d.write_bytes(b"# Disk DescriptorFile\n" + b"#" * (2 * 1024 * 1024))
    with pytest.raises(ValueError, match="too large"):
        TargetSource().open(d)


def test_sparse_vmdk_embedded_descriptor_checked(tmp_path):
    desc = DESCRIPTOR_OUT.ljust(512, b"\0")
    header = bytearray(512 * 2)
    header[0:4] = b"KDMV"
    struct.pack_into("<Q", header, 28, 2)
    struct.pack_into("<Q", header, 36, 1)
    (tmp_path / "s.vmdk").write_bytes(bytes(header) + desc)
    with pytest.raises(ValueError, match="outside"):
        TargetSource().open(tmp_path / "s.vmdk")


def test_cowd_refused(tmp_path):
    (tmp_path / "old.raw").write_bytes(b"COWD" + b"\0" * 2044)
    with pytest.raises(ValueError, match="COWD"):
        TargetSource().open(tmp_path / "old.raw")


def test_vhd_differencing_refused(tmp_path):
    footer = bytearray(512)
    footer[0:8] = b"conectix"
    struct.pack_into(">I", footer, 60, 4)
    (tmp_path / "child.vhd").write_bytes(b"\0" * 4096 + bytes(footer))
    with pytest.raises(ValueError, match="differencing"):
        TargetSource().open(tmp_path / "child.vhd")


def test_directory_uses_plain_loader(tree):
    (tree / "vm.vmx").write_text('scsi0:0.fileName = "/etc/passwd"\n')
    ev = TargetSource().open(tree)
    assert type(ev.target._loader).__name__ in ("DirLoader", "KapeLoader")


def test_child_vmdk_with_parent_hint_refused(tmp_path):
    (tmp_path / "base.vmdk").write_bytes(b"\0" * 1024)
    d = tmp_path / "child.vmdk"
    d.write_text('# Disk DescriptorFile\nversion=1\nparentCID=1234abcd\n'
                 'parentFileNameHint="/Users/someone/secret.vmdk"\nRW 2048 SPARSE "child-s001.vmdk"\n')
    (tmp_path / "child-s001.vmdk").write_bytes(b"\0" * 1024)
    with pytest.raises(ValueError, match="child"):
        TargetSource().open(d)


def test_extent_that_is_itself_a_descriptor_is_checked(tmp_path):
    (tmp_path / "inner.vmdk").write_bytes(DESCRIPTOR_OUT)
    outer = tmp_path / "outer.vmdk"
    outer.write_text('# Disk DescriptorFile\nversion=1\nparentCID=ffffffff\nRW 2048 FLAT "inner.vmdk" 0\n')
    with pytest.raises(ValueError, match="outside"):
        TargetSource().open(outer)


def test_self_referencing_descriptor_terminates(tmp_path):
    loop = tmp_path / "loop.vmdk"
    loop.write_text('# Disk DescriptorFile\nversion=1\nRW 2048 FLAT "loop.vmdk" 0\n')
    TargetSource().can_open(loop)
    from investigation.modules.sources.target import check_disk_references
    check_disk_references(loop)


def test_unparseable_vhdx_fails_closed(tmp_path):
    (tmp_path / "bad.vhdx").write_bytes(b"vhdxfile" + b"\0" * 4096)
    with pytest.raises(ValueError, match="cannot verify VHDX"):
        TargetSource().open(tmp_path / "bad.vhdx")


def test_short_vmdk_magic_poc_refused(tmp_path):
    secret = tmp_path / "other_case" / "secret.dd"
    secret.parent.mkdir()
    secret.write_bytes(b"HOST-SECRET" * 100)
    ev_dir = tmp_path / "case"
    ev_dir.mkdir()
    f = ev_dir / "evidence.raw"
    f.write_text(f'# Di\nparentCID=abcdef01\nparentFileNameHint="{secret}"\n')
    with pytest.raises(ValueError):
        TargetSource().open(f)


def test_jail_blocks_any_host_open_during_target_open(tmp_path, monkeypatch):
    """Whatever the format trick, dissect may not open files outside the evidence while loading it."""
    from investigation.modules.sources.target import host_file_jail

    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"x")
    inside = tmp_path / "case" / "disk.E01"
    inside.parent.mkdir()
    inside.write_bytes(b"x")
    sibling_segment = inside.with_name("disk.E02")
    sibling_segment.write_bytes(b"x")
    neighbour = inside.with_name("other_case.img")
    neighbour.write_bytes(b"x")
    with host_file_jail(inside):
        open(inside, "rb").close()
        open(sibling_segment, "rb").close()
        with pytest.raises(PermissionError):
            open(outside, "rb")
        with pytest.raises(PermissionError):
            neighbour.open("rb")
    open(outside, "rb").close()


def test_qcow2_backing_file_refused(tmp_path):
    import struct as st

    hdr = bytearray(512)
    hdr[0:4] = b"QFI\xfb"
    st.pack_into(">I", hdr, 4, 3)
    st.pack_into(">Q", hdr, 8, 200)
    st.pack_into(">I", hdr, 16, 9)
    hdr[200:209] = b"other.img"
    (tmp_path / "other.img").write_bytes(b"\0" * 512)
    (tmp_path / "child.qcow2").write_bytes(bytes(hdr))
    with pytest.raises(ValueError, match="backing"):
        TargetSource().open(tmp_path / "child.qcow2")


@pytest.mark.parametrize("evidence,sibling,ok", [
    ("a.E01", "a.E02", True),
    ("a.E01", "a.EAB", True),
    ("case.Ex01", "case.Ex02", True),
    ("disk.001", "disk.002", True),
    ("disk.vmdk", "disk-s001.vmdk", True),
    ("disk.vmdk", "disk-flat.vmdk", True),
    ("a.E01", "april_case.dd", False),
    ("a.E01", "a_other.E01", False),
    (".hidden", "anything.dd", False),
    ("disk.vmdk", "disk-secret.txt", False),
])
def test_jail_sibling_rules(tmp_path, evidence, sibling, ok):
    from investigation.modules.sources.target import host_file_jail

    (tmp_path / evidence).write_bytes(b"x")
    (tmp_path / sibling).write_bytes(b"x")
    with host_file_jail(tmp_path / evidence):
        open(tmp_path / evidence, "rb").close()
        if ok:
            open(tmp_path / sibling, "rb").close()
        else:
            with pytest.raises(PermissionError):
                open(tmp_path / sibling, "rb")
