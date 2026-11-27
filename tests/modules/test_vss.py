import csv
from datetime import datetime, timezone

from investigation.core.registry import ModuleRegistry
from investigation.core.requirements import Context
from investigation.modules.collectors import vss
from investigation.modules.collectors.files import FilesCollector, OsReader
from investigation.modules.collectors.vss import Shadow, VssCollector
from tests.helpers.windows_tree import build_windows_tree

SHADOW = Shadow(7, r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7", "C",
                datetime(2026, 11, 20, 10, 0, tzinfo=timezone.utc), "{abc}")


def _run(tmp_path, shadows, readers=None):
    out = tmp_path / "out"
    out.mkdir()
    extra, warns = {}, []
    opts = {"package_root": out, "extra_files": extra, "warnings": warns, "drives": ["C"]}
    if readers is not None:
        opts["vss_readers"] = readers
    return out, extra, warns, VssCollector().collect(Context(output_dir=out, options=opts), out)


def test_registered_default_off():
    reg = ModuleRegistry(fresh=True)
    reg.discover(user_dir=None, entry_points=False)
    m = reg.get("vss").meta
    assert (m.category, m.priority, m.requires_admin) == ("vss", 110, True)


def test_list_shadows_parses_wmi(monkeypatch):
    def fake(ns, cls, props):
        if cls == "Win32_ShadowCopy":
            return [{"ID": "{abc}", "DeviceObject": r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7",
                     "VolumeName": r"\\?\Volume{g1}" + "\\", "InstallDate": "20261120100000.000000+000"},
                    {"ID": "{x}", "DeviceObject": r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy8",
                     "VolumeName": r"\\?\Volume{nomatch}" + "\\", "InstallDate": None}]
        return [{"DeviceID": r"\\?\Volume{g1}" + "\\", "DriveLetter": "C:"}]
    monkeypatch.setattr(vss, "wmi_query", fake)
    assert vss.list_shadows() == [Shadow(7, SHADOW.device, "C", SHADOW.created_utc, "{abc}")]


def test_vss_copies_into_prefixed_tree(tmp_path, monkeypatch):
    tree = build_windows_tree(tmp_path / "C")
    monkeypatch.setattr(vss, "list_shadows", lambda: [SHADOW])
    out, extra, _, n = _run(tmp_path, [SHADOW], {7: ("C", OsReader(tree, None))})
    key = "vss/7/C/Windows/System32/config/SYSTEM"
    assert n >= 1 and (out / key).is_file()
    assert extra[key]["shadow_id"] == "{abc}"
    assert extra[key]["shadow_created_utc"] == "2026-11-20T10:00:00+00:00"
    rows = list(csv.DictReader(open(out / "vss/shadows.csv", encoding="utf-8-sig")))
    assert rows[0]["index"] == "7" and rows[0]["id"] == "{abc}"


def test_vss_skips_raw_only_targets(tmp_path, monkeypatch):
    tree = build_windows_tree(tmp_path / "C")
    (tree / "$MFT").write_bytes(b"mft")
    monkeypatch.setattr(vss, "list_shadows", lambda: [SHADOW])
    out, _, _, _ = _run(tmp_path, [SHADOW], {7: ("C", OsReader(tree, None))})
    assert not (out / "vss/7/C/$MFT").exists()


def test_no_shadows_is_ok(tmp_path, monkeypatch):
    monkeypatch.setattr(vss, "list_shadows", lambda: [])
    out, _, warns, n = _run(tmp_path, [])
    assert n == 0 and not warns


def test_unopenable_shadow_warns_and_continues(tmp_path, monkeypatch):
    tree = build_windows_tree(tmp_path / "C")
    s8 = Shadow(8, "d8", "C", None, "{x}")
    monkeypatch.setattr(vss, "list_shadows", lambda: [s8, SHADOW])

    def opener(d):
        if d == "d8":
            raise PermissionError("no")
        return None
    monkeypatch.setattr(vss, "open_shadow", opener)
    monkeypatch.setattr(vss, "_reader_for", lambda fh: OsReader(tree, None))
    out, _, warns, n = _run(tmp_path, None)
    assert n >= 1 and any("8" in w for w in warns)
    assert (out / "vss/7/C/Windows/System32/config/SYSTEM").is_file()


def test_files_one_prefix_default_unchanged(tmp_path):
    tree = build_windows_tree(tmp_path / "C")
    extra = {}
    rel = "Windows/System32/config/SYSTEM"
    assert FilesCollector._one(OsReader(tree, None), "C", rel, tmp_path, extra) == 1
    assert f"files/C/{rel}" in extra


def test_open_shadow_uses_device_path(monkeypatch):
    calls = []
    monkeypatch.setattr("builtins.open", lambda *a, **k: calls.append((a, k)) or "fh")
    assert vss.open_shadow(SHADOW.device) == "fh"
    assert calls == [((SHADOW.device, "rb"), {"buffering": 0})]


def test_reader_for_closes_handle_on_failure(monkeypatch):
    class FH:
        closed = False

        def close(self):
            self.closed = True
    fh = FH()
    monkeypatch.setattr(vss, "device_length", lambda f: (_ for _ in ()).throw(OSError("x")))
    try:
        vss._reader_for(fh)
    except OSError:
        pass
    assert fh.closed


def test_list_failure_warns_and_writes_header(tmp_path, monkeypatch):
    def boom():
        raise vss.WmiUnavailable("no wmi")
    monkeypatch.setattr(vss, "list_shadows", boom)
    out, _, warns, n = _run(tmp_path, None)
    assert n == 0 and warns
    assert (out / "vss/shadows.csv").read_text(encoding="utf-8-sig").strip() == "index,id,volume,created_utc"


def test_device_without_digits_skipped(monkeypatch):
    def fake(ns, cls, props):
        if cls == "Win32_ShadowCopy":
            return [{"ID": "{a}", "DeviceObject": "nodigits", "VolumeName": "V", "InstallDate": None}]
        return [{"DeviceID": "V", "DriveLetter": "C:"}]
    monkeypatch.setattr(vss, "wmi_query", fake)
    assert vss.list_shadows() == []


def test_missing_install_date_gives_empty(tmp_path, monkeypatch):
    tree = build_windows_tree(tmp_path / "C")
    s = Shadow(7, "d", "C", None, "{abc}")
    monkeypatch.setattr(vss, "list_shadows", lambda: [s])
    _, extra, _, _ = _run(tmp_path, [s], {7: ("C", OsReader(tree, None))})
    assert extra["vss/7/C/Windows/System32/config/SYSTEM"]["shadow_created_utc"] == ""
