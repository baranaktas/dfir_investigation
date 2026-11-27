# Changelog

## Unreleased

- The executable includes the SigmaHQ core Windows rules (release r2026-07-01), so Sigma runs without `rules update`; a set downloaded with `rules update` replaces the bundled one. The report and `doctor` name the rule source.
- `scripts/benchmark_evtx.py` measures detection on a local copy of EVTX-ATTACK-SAMPLES.
- Commands: a "Commands" section in the report and `commands.csv` list every command found in PowerShell
  history, Security 4688, Sysmon 1, PowerShell 4103/4104, live processes, memory command lines, console
  history from memory and RunMRU. Suspicious commands are marked and reported as findings (INV-CMD-001 to 009).
- cmd.exe console history is recovered from memory images with the Volatility 3 `cmdscan` and `consoles` plugins.
- No size limit on `manifest.json` (folder or zip); a manifest larger than 256 MiB prints a memory note, and
  a zip member that is larger than its header says is rejected.
- The zip question is asked after menu-driven and `--only` collections.
- A collection folder or zip is recognised as a package when its manifest is valid; an invalid
  `manifest.json` fails with a clear error and exit code 2 instead of falling back to a directory.
- Event log rules tuned for log clears, explicit credentials, service installs and WinPmem, with the WinPmem
  and explicit-credential exclusions limited to the exact benign patterns.
- Event logs that exist in both the live system and a shadow copy are counted once.

## 0.1.0 - 2026-11-27

First public release.

- Live collection: 21 volatile-data collectors, raw NTFS file collection in KAPE layout, volume shadow
  copies, WinPmem memory image and raw disk images with MD5/SHA-1/SHA-256.
- Shadow copies: a file identical to the live copy is stored once and listed in the manifest.
- Hashed evidence packages with `manifest.json`, an optional zip of the package and `investigation verify`.
- Progress output during collection and analysis.
- Analysis of collection packages, disk images, VM disks, KAPE output, folders and memory images.
- 50 parser modules feeding one timeline (SQLite, CSV, JSON Lines).
- Detection with 58 built-in rules, Sigma, YARA, IOC matching, live-data rules, Volatility 3 and process-tree checks.
- Self-contained HTML report with findings grouped by ATT&CK tactic, file stories and a filterable timeline.
- Single x64 executable with a double-click console menu.
