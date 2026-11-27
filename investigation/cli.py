"""Command line interface: investigation analyze | doctor | modules | profiles | run."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections import Counter
from pathlib import Path

from investigation import __version__
from investigation.core.collect import DEFAULT_CATEGORIES, collect, default_parent
from investigation.core.frozen import is_frozen
from investigation.core.collect_menu import ask_collection, ask_yes_no, is_arm64, runtime_estimates
from investigation.core.module import ModuleType
from investigation.core.pipeline import InputError, OutputDirError, analyze, default_registry
from investigation.core.preflight import run_preflight
from investigation.core.profiles import Profile, ProfileError, list_profiles, load_profile, resolve
from investigation.core.registry import ModuleRegistry
from investigation.core.requirements import Context, Status, is_admin
from investigation.modules.collectors.volumes import list_volumes

EXIT_OK, EXIT_PARTIAL, EXIT_USAGE = 0, 1, 2
MARK = {Status.OK: "[OK]", Status.MISSING: "[MISSING]", Status.WARN: "[WARN]"}


class CliError(Exception):
    pass


def _default_out(input_path: Path, suffix: str = "report") -> Path:
    return Path.cwd() / f"{input_path.resolve().name}_{suffix}"


def _print_summary(result, out_dir: Path) -> int:
    counts = Counter(str(f.severity) for f in result.findings)
    print(f"Events:   {result.store.count()}")
    sev = ", ".join(f"{s}: {counts.get(s, 0)}" for s in ("critical", "high", "medium", "low", "info"))
    print(f"Findings: {len(result.findings)} ({sev})")
    for f in result.sorted_findings()[:15]:
        print(f"  [{str(f.severity).upper():8}] {f.rule_id:16} {f.title} ({len(f.events)} events)")
    if result.preflight.skipped:
        print(f"Skipped modules: {', '.join(f'{k} ({v})' for k, v in result.preflight.skipped.items())}")
    if result.module_errors:
        print(f"Module errors: {len(result.module_errors)} (see report / investigation.log)")
    print(f"Report:   {out_dir.resolve() / 'report.html'}")
    return EXIT_PARTIAL if (result.module_errors or result.preflight.skipped) else EXIT_OK


def cmd_analyze(args: argparse.Namespace) -> int:
    inp = Path(args.input)
    out = Path(args.out) if args.out else _default_out(inp)
    options = {}
    if args.ioc:
        options["ioc_files"] = args.ioc
    if args.memory:
        options["memory"] = args.memory
    result = analyze(inp, out, profile=args.profile, case_id=args.case or "", examiner=args.examiner or "",
                     allow_install=not args.no_install, force=args.force, options=options)
    return _print_summary(result, out)


def cmd_run(args: argparse.Namespace) -> int:
    inp = Path(args.input)
    out = Path(args.out) if args.out else _default_out(inp, f"{args.module}_report")
    reg = default_registry()
    try:
        reg.get(args.module)
    except KeyError as exc:
        raise CliError(str(exc.args[0])) from None
    profile = Profile("adhoc", f"single module {args.module}", [args.module, "source:*", "output:*"], [])
    result = analyze(inp, out, profile=profile, allow_install=not args.no_install, force=args.force, registry=reg)
    return _print_summary(result, out)


def _dissect_plugin_count() -> int:
    from dissect.target import plugin

    return sum(1 for _ in plugin.plugins())


def _frozen_checks() -> tuple[bool, str] | None:
    """Frozen exe only: dissect discovers plugins from .py files, so a bad bundle loads none."""
    if not is_frozen():
        return None
    try:
        n = _dissect_plugin_count()
    except Exception as exc:
        return False, f"dissect plugins: MISSING ({type(exc).__name__}: {exc})"
    return (n > 0, f"dissect plugins: {n} loaded" if n else "dissect plugins: MISSING (0 loaded; bundle is broken)")


def cmd_doctor(args: argparse.Namespace) -> int:
    reg = default_registry()
    modules = resolve(load_profile(args.profile), reg)
    report = run_preflight(modules, Context(allow_install=False))
    if args.json:
        print(json.dumps({"preflight": report.to_dict(),
                          "load_errors": [{"origin": o, "message": m} for o, m in reg.load_errors]}, indent=2))
        return EXIT_OK if report.ok and not reg.load_errors else EXIT_PARTIAL
    fc = _frozen_checks()
    frozen_ok = fc is None or fc[0]
    print(f"investigation {__version__} - environment check (profile: {args.profile})\n")
    for name, results in report.results.items():
        state = "SKIPPED" if name in report.skipped else "ready"
        print(f"{name}  [{state}]")
        if not results:
            print("    [OK] no requirements")
        for r in results:
            print(f"    {MARK[r.status]:10} {r.requirement}: {r.detail}")
            if r.fix and r.status is not Status.OK:
                print(f"               fix: {r.fix}")
    if fc:
        print(f"\n    {'[OK]' if fc[0] else '[MISSING]':10} {fc[1]}")
    if reg.load_errors:
        print("\nModule load errors:")
        for origin, msg in reg.load_errors:
            print(f"    [ERROR] {origin}: {msg}")
    print(f"\n{len(report.runnable)} module(s) ready, {len(report.skipped)} skipped.")
    return EXIT_OK if report.ok and not reg.load_errors and frozen_ok else EXIT_PARTIAL


def cmd_modules(args: argparse.Namespace) -> int:
    reg = default_registry()
    if args.action == "list":
        mods = reg.by_type(ModuleType(args.type)) if args.type else reg.all()
        for m in mods:
            print(f"{m.meta.type.value:10} {m.meta.name:18} {m.meta.description}")
        return EXIT_OK
    try:
        m = reg.get(args.name)
    except KeyError as exc:
        raise CliError(str(exc.args[0])) from None
    meta = m.meta
    print(f"name:          {meta.name}\ntype:          {meta.type.value}\ndescription:   {meta.description}")
    print(f"platforms:     {', '.join(meta.platforms)}\nrequires admin: {meta.requires_admin}")
    print(f"depends on:    {', '.join(meta.depends_on) or '-'}\nartifacts:     {', '.join(meta.artifacts) or '-'}")
    print("requirements:")
    for r in m.all_requirements():
        print(f"  - {r.describe()}{'' if r.mandatory else ' (optional)'}")
    if not m.all_requirements():
        print("  - none")
    return EXIT_OK


def cmd_profiles(args: argparse.Namespace) -> int:
    if args.action == "list":
        for p in list_profiles():
            print(f"{p.name:16} {p.description}")
        return EXIT_OK
    p = load_profile(args.name)
    print(f"{p.name}: {p.description}\nmodules (run order):")
    for m in resolve(p, default_registry()):
        print(f"  {m.meta.type.value:10} {m.meta.name}")
    return EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    from investigation.core.rules_update import sigma_root, update_sigma

    if args.action == "update":
        try:
            stats = update_sigma(zip_path=Path(args.from_zip) if args.from_zip else None,
                                 **({"url": args.url} if args.url else {}))
        except ValueError as exc:
            raise CliError(f"rules update failed: {exc}") from None
        print(f"Installed {stats['rules']} Sigma rules ({stats['skipped']} archive entries skipped) "
              f"into {sigma_root()}")
        return EXIT_OK
    root = sigma_root()
    if not root.is_dir():
        print(f"No Sigma rules in {root}. Run: investigation rules update")
        return EXIT_PARTIAL
    for sub in sorted(p for p in root.iterdir() if p.is_dir()):
        n = sum(1 for p in sub.rglob("*") if p.suffix in (".yml", ".yaml"))
        version = (sub / "VERSION").read_text().splitlines()[0] if (sub / "VERSION").is_file() else "custom"
        print(f"{sub.name:12} {n:6} rules  {version}")
    return EXIT_OK


def _letter(text: str) -> str:
    return text.strip().rstrip(":").upper()


def cmd_collect(args: argparse.Namespace) -> int:
    if args.all and args.only:
        raise CliError("--all and --only cannot be combined")
    reg = ModuleRegistry()
    reg.discover(user_dir=None, entry_points=False)
    collectors = reg.by_type(ModuleType.COLLECTOR)
    categories = list(dict.fromkeys(c.meta.category for c in collectors))
    valid = sorted({c.meta.name for c in collectors} | set(categories))
    interactive = not (args.all or args.only) and sys.stdin.isatty()
    auto = bool(args.all or args.yes)
    ask = sys.stdin.isatty() and not auto
    ask_zip = sys.stdin.isatty() and not args.all
    confirm = ask_yes_no if ask else (lambda _: auto)
    declined_detail = "declined by examiner" if ask else "not confirmed (non-interactive; use --yes)"

    selection: list[str] | None = None
    if args.only:
        selection = [t.strip() for t in args.only.split(",") if t.strip()]
        unknown = [t for t in selection if t not in valid]
        if unknown:
            raise CliError(f"unknown name(s): {', '.join(unknown)}. Valid names: {', '.join(valid)}")
    elif args.all:
        selection = [c for c in categories if c != "disk"]
    elif interactive:
        pass

    volumes = list_volumes()
    system = next((v.letter for v in volumes if v.is_system), None)
    system = _letter(system or os.environ.get("SystemDrive", "C:"))
    drives = [system]
    if args.drives:
        drives = [_letter(d) for d in args.drives.split(",") if d.strip()]
        have = [_letter(v.letter) for v in volumes]
        bad = [d for d in drives if d not in have]
        if bad:
            raise CliError(f"unknown drive(s): {', '.join(bad)}. Available: {', '.join(have) or 'none'}")
    image_drives: list[str] = []
    if args.image_drives:
        image_drives = [_letter(d) for d in args.image_drives.split(",") if d.strip()]
        have = [_letter(v.letter) for v in volumes]
        bad = [d for d in image_drives if d not in have]
        if bad:
            raise CliError(f"unknown drive(s): {', '.join(bad)}. Available: {', '.join(have) or 'none'}")
    if interactive:
        out_dir = Path(args.out) if args.out else Path(default_parent())
        choice = ask_collection(volumes, arm64=is_arm64(), estimates=runtime_estimates(drives),
                                output=str(out_dir), fixed_drives=drives if args.drives else (),
                                fixed_image_drives=image_drives, estimate_fn=runtime_estimates)
        if choice is None:
            print("Collection cancelled.")
            return EXIT_OK
        selection, drives = choice.categories, choice.drives
        image_drives = choice.image_drives
        confirm = lambda _: True

    if args.disk_image:
        base = selection if selection is not None else list(DEFAULT_CATEGORIES)
        selection = [*base, "disk"] if "disk" not in base else base

    if not is_admin():
        print("[warn] not running as administrator/root; some collectors will be skipped or incomplete.")
    try:
        result = collect(selection, out=Path(args.out) if args.out else None, case_id=args.case or "",
                         examiner=args.examiner or "", confirm=confirm, declined_detail=declined_detail, registry=reg, options={"drives": drives, **({"image_drives": image_drives} if image_drives else {})})
    except KeyError as exc:
        raise CliError(str(exc.args[0]) if exc.args else "unknown collector selection") from exc
    except (KeyboardInterrupt, Exception) as exc:
        root = getattr(exc, "package_root", None)
        if root is not None:
            _offer_zip(Path(root), args.zip, ask_zip)
        raise
    counts = Counter(m["status"] for m in result.manifest.get("modules", []))
    print(f"Package: {result.root}")
    print(f"Status:  {result.manifest.get('status', '')} ({', '.join(f'{k}: {v}' for k, v in sorted(counts.items()))})")
    _offer_zip(result.root, args.zip, ask_zip)
    return EXIT_OK if result.exit_code == 0 else EXIT_PARTIAL


def _size_text(path: Path) -> str:
    from investigation.core.console import human_bytes

    total = sum(f.stat().st_size for f in path.rglob("*") if f.is_file()) if path.is_dir() else path.stat().st_size
    return human_bytes(total)


def _offer_zip(root: Path, requested: bool, interactive: bool) -> None:
    """After a collection (whatever its status): zip the package when --zip was given or the examiner says yes."""
    from investigation.core.archive import ZipSkipped, zip_package

    if not requested and not (interactive and ask_yes_no("Compress the package into a zip?")):
        return
    try:
        zip_path, sidecar = zip_package(root)
    except ZipSkipped as exc:
        print(f"Zip skipped: {exc}")
        return
    except OSError as exc:
        print(f"Zip failed: {exc}")
        return
    print(f"Folder: {_size_text(root)}  Zip: {_size_text(zip_path)}")
    print(f"Zip:    {zip_path}")
    print(f"SHA-256: {sidecar}")
    print(f"You can delete the folder after checking the zip with: investigation verify {zip_path}")


def cmd_verify(args: argparse.Namespace) -> int:
    from investigation.core.package import MANIFEST_NAME, verify_manifest

    root = Path(args.package)
    if root.is_file() and root.name.casefold().endswith(".zip"):
        from investigation.core.archive import sidecar_for
        from investigation.core.package import hash_file, verify_zip

        problems = verify_zip(root)
        side = sidecar_for(root)
        if side.is_file():
            parts = side.read_text(encoding="utf-8").split()
            if not parts or parts[0].lower() != hash_file(root)["sha256"]:
                problems.append(f"zip does not match {side.name}")
    elif (root / MANIFEST_NAME).is_file():
        problems = verify_manifest(root, skip_images=False)
    else:
        raise CliError(f"{root} is not a collection package (no {MANIFEST_NAME})")
    if not problems:
        print(f"OK: every file in {root} matches the manifest")
        return EXIT_OK
    for p in problems:
        print(f"[PROBLEM] {p}")
    print(f"{len(problems)} problem(s) found")
    return EXIT_PARTIAL


def cmd_menu(args) -> int:
    from investigation import console_menu

    return console_menu.run_menu()


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="investigation", description="Modular Windows incident response framework")
    ap.add_argument("--version", action="version", version=f"investigation {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyze evidence (folder, collection, image) and write a report")
    a.add_argument("input")
    a.add_argument("-o", "--out", help="output directory (default: ./<input>_report)")
    a.add_argument("--profile", default="full")
    a.add_argument("--case", help="case id")
    a.add_argument("--examiner", help="examiner name")
    a.add_argument("--no-install", action="store_true", help="never auto-install missing python packages")
    a.add_argument("--force", action="store_true", help="overwrite a non-empty output directory")
    a.add_argument("--ioc", action="append", metavar="FILE", help="IOC list (hashes/IPs/domains/URLs/files); repeatable")
    a.add_argument("--memory", metavar="IMAGE", help="memory image to analyze with Volatility 3 alongside the input")
    a.set_defaults(func=cmd_analyze)

    r = sub.add_parser("run", help="run a single module (plus sources and outputs)")
    r.add_argument("module")
    r.add_argument("input")
    r.add_argument("-o", "--out")
    r.add_argument("--no-install", action="store_true")
    r.add_argument("--force", action="store_true")
    r.set_defaults(func=cmd_run)

    d = sub.add_parser("doctor", help="check the environment and every module's requirements")
    d.add_argument("--profile", default="full")
    d.add_argument("--json", action="store_true")
    d.set_defaults(func=cmd_doctor)

    m = sub.add_parser("modules", help="list modules or show one")
    msub = m.add_subparsers(dest="action", required=True)
    ml = msub.add_parser("list")
    ml.add_argument("--type", choices=[t.value for t in ModuleType])
    mi = msub.add_parser("info")
    mi.add_argument("name")
    m.set_defaults(func=cmd_modules)

    p = sub.add_parser("profiles", help="list profiles or show a profile's resolved modules")
    psub = p.add_subparsers(dest="action", required=True)
    psub.add_parser("list")
    ps = psub.add_parser("show")
    ps.add_argument("name")
    p.set_defaults(func=cmd_profiles)
    c = sub.add_parser("collect", help="collect volatile data and artifacts from this live system")
    c.add_argument("--all", action="store_true", help="all categories (no disk image), no prompts")
    c.add_argument("--only", metavar="NAMES", help="comma-separated module or category names")
    c.add_argument("--drives", metavar="C,D", help="drives to collect files from (default: system drive)")
    c.add_argument("-o", "--out", help="parent directory for the collection package")
    c.add_argument("--case", help="case id")
    c.add_argument("--examiner", help="examiner name")
    c.add_argument("--image-drives", metavar="T", help="drives whose physical disks are imaged (default: --drives)")
    c.add_argument("--disk-image", action="store_true", help="also image the physical disk(s) behind the drives")
    c.add_argument("--zip", action="store_true", help="compress the package into a zip when the collection ends")
    c.add_argument("--yes", action="store_true", help="answer yes to confirmation prompts")
    c.set_defaults(func=cmd_collect)
    v = sub.add_parser("verify", help="re-hash every file of a collection package against its manifest")
    v.add_argument("package")
    v.set_defaults(func=cmd_verify)
    mn = sub.add_parser("menu", help="interactive console menu")
    mn.set_defaults(func=cmd_menu)
    ru = sub.add_parser("rules", help="install/update Sigma rules")
    rsub = ru.add_subparsers(dest="action", required=True)
    up = rsub.add_parser("update", help="download the SigmaHQ Windows rules (network)")
    up.add_argument("--url", help="alternative sigma_core.zip URL")
    up.add_argument("--from-zip", help="install from a local sigma_core.zip (offline)")
    rsub.add_parser("status")
    ru.set_defaults(func=cmd_rules)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    try:
        return args.func(args)
    except (InputError, OutputDirError, ProfileError, CliError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
