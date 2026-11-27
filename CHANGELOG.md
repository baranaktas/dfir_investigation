# Changelog

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
