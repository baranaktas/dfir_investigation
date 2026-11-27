import hashlib
import importlib.util
import io
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "fetch_sigma.py"
RULE = b"title: t\nid: 11111111-1111-1111-1111-111111111111\nlogsource:\n  product: windows\n  service: security\n"


def _zip_bytes(extra=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("rules/windows/builtin/security/win_a.yml", RULE)
        z.writestr("rules/linux/lnx_a.yml", RULE)
        z.writestr("version.txt", "Release Date: 2026-01-01\n")
        for name in extra or ():
            z.writestr(name, RULE)
    return buf.getvalue()


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _load(tmp_path, monkeypatch, data):
    spec = importlib.util.spec_from_file_location("fetch_sigma", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "DEST", tmp_path / "sigma")
    monkeypatch.setattr(mod, "SIGMA_BUNDLED_SHA256", hashlib.sha256(_zip_bytes()).hexdigest())
    monkeypatch.setattr(mod.urllib.request, "urlopen", lambda url, timeout=None, context=None: _Resp(data))
    return mod


def test_fetch_extracts_windows_rules(tmp_path, monkeypatch):
    mod = _load(tmp_path, monkeypatch, _zip_bytes())
    (tmp_path / "sigma").mkdir()
    (tmp_path / "sigma" / "README.md").write_text("keep")
    assert mod.main() == 0
    dest = tmp_path / "sigma"
    assert (dest / "rules" / "windows" / "builtin" / "security" / "win_a.yml").is_file()
    assert not (dest / "rules" / "linux").exists()
    assert (dest / "README.md").read_text() == "keep"
    assert (dest / "VERSION").read_text().strip() == mod.SIGMA_BUNDLED_TAG


def test_fetch_skips_when_present(tmp_path, monkeypatch):
    mod = _load(tmp_path, monkeypatch, _zip_bytes())
    assert mod.main() == 0

    def boom(*a, **k):
        raise AssertionError("downloaded again")

    monkeypatch.setattr(mod.urllib.request, "urlopen", boom)
    assert mod.main() == 0


def test_fetch_mismatch_leaves_nothing(tmp_path, monkeypatch):
    mod = _load(tmp_path, monkeypatch, _zip_bytes(["rules/windows/x.yml"]))
    assert mod.main() == 1
    assert list((tmp_path / "sigma").iterdir()) == []
