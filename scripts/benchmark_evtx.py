"""Measure detection on a local copy of EVTX-ATTACK-SAMPLES (nothing is downloaded).

Each .evtx file is analyzed on its own. A file counts as detected when any finding is reported and as matched when
a finding carries the ATT&CK tactic named by the file's folder (built-in rules through their technique ids, Sigma
rules through their attack.* tags).

Usage: python scripts/benchmark_evtx.py <samples folder> [-o results_dir] [--builtin-only]
"""

from __future__ import annotations

import argparse
import csv
import logging
import shutil
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from investigation.core.attack import TACTICS, tactics_for
from investigation.core.pipeline import analyze

LABELS = {label.casefold(): slug for slug, label in TACTICS}
FIELDS = ["file", "tactic", "events", "detected", "matched", "rule_ids", "error"]


def tactic_of(path: Path, root: Path) -> str:
    for part in path.relative_to(root).parts[:-1]:
        slug = LABELS.get(part.casefold())
        if slug:
            return slug
    return ""


def analyze_file(file: Path, tactic: str, builtin_only: bool) -> dict:
    work = Path(tempfile.mkdtemp(prefix="bench-"))
    row = {"file": "", "tactic": tactic, "events": 0, "detected": 0, "matched": 0, "rule_ids": "", "error": ""}
    store = None
    try:
        (work / "in").mkdir()
        shutil.copy2(file, work / "in" / file.name)
        options = {}
        if builtin_only:
            (work / "no-sigma").mkdir()
            options["sigma_paths"] = [str(work / "no-sigma")]
        result = analyze(work / "in", work / "out", profile="full", allow_install=False, options=options)
        store = result.store
        row["events"] = store.count()
        row["rule_ids"] = " ".join(sorted({f.rule_id for f in result.findings}))
        row["detected"] = int(bool(result.findings))
        row["matched"] = int(bool(tactic) and any(tactic in tactics_for(f) for f in result.findings))
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"[:200]
    finally:
        if store is not None:
            store.close()
        shutil.rmtree(work, ignore_errors=True)
    return row


def run(samples: Path, builtin_only: bool = False, progress: bool = False) -> list[dict]:
    rows = []
    files = sorted(samples.rglob("*.evtx"))
    start = time.time()
    for i, file in enumerate(files, 1):
        row = analyze_file(file, tactic_of(file, samples), builtin_only)
        row["file"] = file.relative_to(samples).as_posix()
        rows.append(row)
        if progress and i % 20 == 0:
            print(f"{i}/{len(files)} {time.time() - start:.0f}s", flush=True)
    return rows


def summarize(rows: list[dict]) -> list[tuple[str, int, int, int]]:
    by: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for r in rows:
        b = by[r["tactic"] or "(none)"]
        b[0] += 1
        b[1] += r["detected"]
        b[2] += r["matched"]
    table = [(t, *b) for t, b in sorted(by.items())]
    table.append(("TOTAL", *(sum(b[i] for b in by.values()) for i in range(3))))
    return table


def _pct(n: int, d: int) -> str:
    return f"{100 * n / d:.0f}%" if d else "-"


def render(table: list[tuple[str, int, int, int]]) -> str:
    lines = ["| Tactic | Files | Any finding | Rate | Finding with the tactic | Rate |", "|---|---:|---:|---:|---:|---:|"]
    for t, n, d, m in table:
        lines.append(f"| {t} | {n} | {d} | {_pct(d, n)} | {m} | {_pct(m, n)} |")
    return "\n".join(lines) + "\n"


def write_results(rows: list[dict], table: list[tuple[str, int, int, int]], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with (out / "results.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    (out / "results.md").write_text(render(table), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("samples", type=Path, help="folder with EVTX-ATTACK-SAMPLES")
    ap.add_argument("-o", "--output", type=Path, default=Path("benchmark_results"))
    ap.add_argument("--builtin-only", action="store_true", help="do not load any Sigma rules")
    args = ap.parse_args(argv)
    if not args.samples.is_dir():
        print(f"not a folder: {args.samples}", file=sys.stderr)
        return 2
    logging.disable(logging.CRITICAL)
    try:
        rows = run(args.samples, args.builtin_only, progress=True)
    finally:
        logging.disable(logging.NOTSET)
    if not rows:
        print("no .evtx files found", file=sys.stderr)
        return 2
    table = summarize(rows)
    write_results(rows, table, args.output)
    print(render(table))
    errors = sum(1 for r in rows if r["error"])
    print(f"errors: {errors}; results in {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
