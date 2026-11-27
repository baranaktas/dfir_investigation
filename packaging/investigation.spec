import pkgutil
from pathlib import Path

import dissect
from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata

ROOT = Path(SPECPATH).resolve().parent
PKG = ROOT / "investigation"


def tree(pattern, dest):
    return [(str(p), f"investigation/{dest}") for p in sorted(PKG.glob(pattern)) if p.is_file()]


datas = []
datas += [(str(p), f"investigation/{p.parent.relative_to(PKG).as_posix()}") for p in sorted((PKG / "rules").rglob("*")) if p.is_file()]
datas += tree("profiles/*.yaml", "profiles")
datas += tree("templates/*", "templates")
datas += tree("artifacts/*.yaml", "artifacts")
datas += tree("resources/winpmem/*.exe", "resources/winpmem")
datas += [(str(p), f"investigation/{p.parent.relative_to(PKG).as_posix()}") for p in sorted((PKG / "resources" / "sigma").rglob("*")) if p.is_file()]
datas += collect_data_files("dissect.target")
datas += collect_data_files("dissect.target", include_py_files=True, subdir="plugins")
datas += collect_data_files("volatility3", include_py_files=True)

for dist in [
    "investigation", "dissect.target", "dissect.eventlog", "dissect.shellitem", "dissect.cim",
    "dissect.thumbcache", "dissect.ole", "dissect.executable", "dissect.fat", "dissect.fve",
    "dissect.archive", "volatility3", "yara-python", "pysigma", "pyyaml", "jinja2", "psutil",
    "pywin32", "pycryptodome",
]:
    try:
        datas += copy_metadata(dist)
    except Exception as exc:
        print(f"WARNING: no metadata for {dist}: {exc}")

dissect_pkgs = [m.name for m in pkgutil.iter_modules(dissect.__path__, prefix="dissect.") if m.ispkg]
hiddenimports = (
    sum((collect_submodules(name) for name in dissect_pkgs), [])
    + collect_submodules("investigation")
    + collect_submodules("volatility3")
    + ["win32timezone", "pythoncom", "pywintypes"]
)

a = Analysis(
    [str(ROOT / "packaging" / "entry.py")],
    pathex=[str(ROOT)],
    datas=datas,
    hiddenimports=hiddenimports,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="investigation",
    console=True,
    uac_admin=True,
    upx=False,
    target_arch=None,
)
