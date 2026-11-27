"""Build a minimal Windows system tree from the dissect.target sample files."""

from __future__ import annotations

import gzip
import shutil
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "windows"
USER = "IEUser"
USER_SID = "S-1-5-21-1-2-3-1001"

LAYOUT = {
    "MPCMDRUN.EXE-962E6200.pf": "Windows/Prefetch/MPCMDRUN.EXE-962E6200.pf",
    "Amcache.hve": "Windows/AppCompat/Programs/Amcache.hve",
    "SRUDB.dat": "Windows/System32/sru/SRUDB.dat",
    "Microsoft-Windows-Windows Defender%4Operational.evtx":
        "Windows/System32/winevt/Logs/Microsoft-Windows-Windows Defender%4Operational.evtx",
    "pestudio.lnk": f"Users/{USER}/AppData/Roaming/Microsoft/Windows/Recent/pestudio.lnk",
    "5f7b5f1e01b83767.automaticDestinations-ms":
        f"Users/{USER}/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/5f7b5f1e01b83767.automaticDestinations-ms",
    "ActivitiesCache.db": f"Users/{USER}/AppData/Local/ConnectedDevicesPlatform/L.{USER}/ActivitiesCache.db",
}


def build_windows_tree(dest: Path) -> Path:
    dest = Path(dest)
    config = dest / "Windows/System32/config"
    config.mkdir(parents=True, exist_ok=True)
    with gzip.open(FIXTURES / "SYSTEM.gz", "rb") as src, open(config / "SYSTEM", "wb") as out:
        shutil.copyfileobj(src, out)
    for name, rel in LAYOUT.items():
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(FIXTURES / name, target)
    return dest


def software_hive():
    from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue

    hive = VirtualHive()

    def key(path: str, **values: str) -> None:
        k = VirtualKey(hive, path)
        for name, value in values.items():
            k.add_value(name, VirtualValue(hive, name, value))
        hive.map_key(path, k)

    key("Microsoft\\Windows NT\\CurrentVersion", SystemRoot="C:\\Windows", ProductName="Windows 10 Pro",
        CurrentBuild="19045")
    key(f"Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{USER_SID}", ProfileImagePath=f"C:\\Users\\{USER}")
    return hive


def open_virtual_target(path: Path, software: bool = True):
    """Target.open plus a virtual SOFTWARE hive (real images always have one)."""
    from dissect.target import Target

    target = Target.open(path)
    if software and target.os == "windows":
        target.registry.add_hive(
            "HKEY_LOCAL_MACHINE",
            "HKEY_LOCAL_MACHINE\\SOFTWARE",
            software_hive(),
            target.fs.path("sysvol/windows/system32/config/SOFTWARE"),
        )
    return target


def user_hive(keys: dict[str, dict[str, object]]):
    """A virtual NTUSER.DAT: {key path: {value name: value}}."""
    from dissect.target.helpers.regutil import VirtualHive, VirtualKey, VirtualValue

    hive = VirtualHive()
    for path, values in keys.items():
        k = VirtualKey(hive, path)
        for name, value in values.items():
            k.add_value(name, VirtualValue(hive, name, value))
        hive.map_key(path, k)
    return hive


def add_user_hive(target, hive, sid: str = USER_SID) -> None:
    """Map a virtual NTUSER hive for `sid` the way dissect maps real ones."""
    reg = target.registry
    reg.load_user_hives()
    reg.add_hive(sid, f"HKEY_USERS\\{sid}", hive, target.fs.path(f"sysvol/users/{USER}/ntuser.dat"))
    details = next(d for d in target.user_details.all() if d.user.sid == sid)
    reg._hives_to_users[hive] = details
