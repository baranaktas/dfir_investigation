import hashlib
import importlib.util
import io
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "fetch_winpmem.py"


def _load(tmp_path, monkeypatch, opener):
    spec = importlib.util.spec_from_file_location("fetch_winpmem", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "DEST", tmp_path)
    monkeypatch.setattr(mod, "WINPMEM_SHA256", hashlib.sha256(b"good").hexdigest())
    monkeypatch.setattr(mod.urllib.request, "urlopen", opener)
    return mod


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_fetch_success(tmp_path, monkeypatch):
    mod = _load(tmp_path, monkeypatch, lambda url, timeout=None, context=None: _Resp(b"good"))
    assert mod.main() == 0
    assert [p.name for p in tmp_path.iterdir()] == [mod.WINPMEM_NAME]


def test_fetch_mismatch_leaves_nothing(tmp_path, monkeypatch):
    mod = _load(tmp_path, monkeypatch, lambda url, timeout=None, context=None: _Resp(b"evil"))
    assert mod.main() == 1
    assert list(tmp_path.iterdir()) == []


def test_fetch_exception_leaves_nothing(tmp_path, monkeypatch):
    class Bad(_Resp):
        def read(self, *a):
            (tmp_path / (mod.WINPMEM_NAME + ".part")).write_bytes(b"half")
            raise OSError("reset")

    mod = _load(tmp_path, monkeypatch, lambda url, timeout=None, context=None: Bad(b""))
    with pytest.raises(OSError):
        mod.main()
    assert list(tmp_path.iterdir()) == []


def test_existing_verified_file_is_not_downloaded(tmp_path, monkeypatch):
    def never(*a, **k):
        raise AssertionError("should not download")

    mod = _load(tmp_path, monkeypatch, never)
    (tmp_path / mod.WINPMEM_NAME).write_bytes(b"good")
    assert mod.main() == 0


def test_download_uses_certifi_bundle(tmp_path, monkeypatch):
    seen = {}

    def opener(url, timeout=None, context=None):
        seen["context"] = context
        return _Resp(b"good")

    mod = _load(tmp_path, monkeypatch, opener)
    assert mod.main() == 0
    assert seen["context"] is not None
