"""Numbered console menu shown when the exe is double-clicked (drives the CLI)."""
import os
import socket
import sys
import time
from pathlib import Path

from investigation import __version__

CLEAR = "\033[2J\033[H"
_GROUPS = [
    ("EVIDENCE", [("1", "Collect evidence", "live data, files, memory, disk image"),
                  ("2", "Analyze", "examine a package, build the HTML report")]),
    ("TOOLS", [("3", "Verify a package", "re-check all hashes"),
               ("4", "Environment check", "what is installed / missing"),
               ("5", "Update Sigma rules", "download rules (internet)")]),
]


def _enable_vt() -> bool:
    """Turn on ANSI escape processing in the Windows console; True when escapes will work."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        k32 = ctypes.windll.kernel32
        handle = k32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not k32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(k32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def _header(base: Path, admin: bool) -> list[str]:
    rows = [f"Investigation {__version__}", f"Host:    {socket.gethostname()}",
            f"Admin:   {'yes' if admin else 'no'}", f"Output:  {base}"]
    width = max(len(r) for r in rows) + 2
    return ["+" + "-" * width + "+", *[f"| {r.ljust(width - 1)}|" for r in rows], "+" + "-" * width + "+"]


def list_packages(base: Path) -> list[Path]:
    pk = [p for p in Path(base).glob("INV_*") if (p / "manifest.json").is_file()]
    return sorted(pk, key=lambda p: p.name, reverse=True)


def _resolve(text: str, base: Path) -> Path:
    t = text.strip()
    if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'":
        t = t[1:-1].strip()
    p = Path(os.path.expanduser(t))
    return p if p.is_absolute() else Path(base) / p


def _default_open():
    return getattr(os, "startfile", None)


def run_menu(input_fn=input, print_fn=print, run_cli=None, base_dir=None, open_fn=None) -> int:
    from investigation.core.collect import default_parent
    from investigation.core.requirements import is_admin

    if run_cli is None:
        from investigation.cli import main as run_cli
    base = Path(base_dir) if base_dir is not None else default_parent()
    open_fn = open_fn or _default_open()

    def ask(prompt):
        return input_fn(prompt).strip()

    def pick_package():
        pkgs = list_packages(base)
        while True:
            for i, p in enumerate(pkgs, 1):
                print_fn(f"  {i}) {p.name}")
            print_fn("  p) Type a path")
            print_fn("  0) Back")
            c = ask("Package: ")
            if c == "0":
                return None
            if c.lower() == "p":
                typed = ask("Path: ")
                return str(_resolve(typed, base)) if typed else None
            if c.isdigit() and 1 <= int(c) <= len(pkgs):
                return str(pkgs[int(c) - 1])

    def call(argv):
        try:
            rc = run_cli(argv)
            return rc if isinstance(rc, int) else 0
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
        except KeyboardInterrupt:
            print_fn("Interrupted")
        except Exception as exc:
            print_fn(f"error: {exc}")
        return None

    def execute(argv):
        call(argv)
        ask("Press Enter to return to the menu")

    def analyze():
        pkg = pick_package()
        if pkg is None:
            return
        default = str(Path(str(Path(pkg)).rstrip("\\/") + "_report"))
        typed = ask(f"Report folder [{default}]: ")
        op = _resolve(typed, base) if typed else Path(default)
        argv = ["analyze", pkg, "-o", str(op), "--profile", "full"]
        if op.is_dir() and any(op.iterdir()):
            if ask("Output folder exists. Overwrite? (y/N) ").lower() != "y":
                return
            argv.append("--force")
        started = time.time()
        rc = call(argv)
        report = op / "report.html"
        if (rc in (0, 1) and report.is_file() and report.stat().st_mtime >= started
                and ask("Open report? (y/N) ").lower() == "y"):
            if open_fn:
                open_fn(report)
            else:
                print_fn(str(report))
        ask("Press Enter to return to the menu")

    def verify():
        pkg = pick_package()
        if pkg is not None:
            execute(["verify", pkg])

    vt_ok = _enable_vt()

    def clear():
        print_fn(CLEAR if vt_ok else "\n" * 3)

    def collect_flow():
        from investigation.core.collect_menu import ask_collection, is_arm64, runtime_estimates
        from investigation.modules.collectors.volumes import list_volumes

        choice = ask_collection(list_volumes, input_fn=input_fn, print_fn=print_fn, arm64=is_arm64(),
                                estimates=runtime_estimates(), estimate_fn=runtime_estimates, output=str(base),
                                resolve_output=lambda t: _resolve(t, base))
        if choice is None:
            ask("Press Enter to return to the menu")
            return
        argv = ["collect", "--only", ",".join(choice.categories), "--drives", ",".join(choice.drives),
                "--yes", "-o", choice.output]
        if choice.image_drives:
            argv += ["--image-drives", ",".join(choice.image_drives)]
        execute(argv)

    actions = {"1": collect_flow, "2": analyze, "3": verify,
               "4": lambda: execute(["doctor"]), "5": lambda: execute(["rules", "update"])}
    while True:
        clear()
        for line in _header(base, is_admin()):
            print_fn(line)
        for title, items in _GROUPS:
            print_fn("")
            print_fn(f" {title}")
            for key, name, desc in items:
                print_fn(f"  {key}  {name:<20} {desc}")
        print_fn("")
        print_fn("  0  Exit")
        try:
            c = ask("> ")
            if c == "0":
                return 0
            if c in actions:
                clear()
                actions[c]()
        except EOFError:
            return 0
        except KeyboardInterrupt:
            print_fn("Bye")
            return 0
