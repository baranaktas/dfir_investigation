# Investigation

**A Windows incident response tool: collect evidence from a live host, then analyze it into a timeline and an
HTML report with findings grouped by MITRE ATT&CK tactic.**

[![CI](https://github.com/baranaktas/dfir_investigation/actions/workflows/ci.yml/badge.svg)](https://github.com/baranaktas/dfir_investigation/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/baranaktas/dfir_investigation)](https://github.com/baranaktas/dfir_investigation/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.12%20%7C%203.13-3776AB)

Investigation has two parts that ship in the same program:

- **Collector**: runs on the Windows host under investigation, with administrator rights. It saves volatile
  data (processes, network connections, services and more) as CSV files, copies registry hives, event logs,
  NTFS metadata and other artifacts, and can take a memory image and raw disk images. Everything goes into
  one package folder with a SHA-256 for every file.
- **Analyzer**: reads a collection package, a disk image, a KAPE collection, a folder or a memory image,
  turns the artifacts into one timeline, runs detection rules and writes a self-contained HTML report.

For Windows there is a single executable, `investigation.exe`, with a numbered console menu. It contains the
Python runtime, so nothing has to be installed on the host.

| | Windows | macOS, Linux |
|---|---|---|
| `investigation.exe` | Yes (x64 build) | No |
| Collection | Yes | No |
| Analysis | Yes (executable or from source) | Yes, from source with Python 3.12 or 3.13 |

> **Status:** version 0.1.0, the first public release. See [Test status](#test-status) for what has been
> tested and what has not. Detection accuracy has not been measured against a labelled data set yet.

---

## Contents

- [Quick start (Windows executable)](#quick-start-windows-executable)
- [Installing from source](#installing-from-source)
- [Collecting evidence](#collecting-evidence)
- [Analyzing evidence](#analyzing-evidence)
- [The report](#the-report)
- [What is parsed](#what-is-parsed)
- [Detection](#detection)
- [How evidence is handled](#how-evidence-is-handled)
- [Command-line reference](#command-line-reference)
- [Extending](#extending)
- [Test status](#test-status)
- [Limitations](#limitations)
- [License](#license)

## Quick start (Windows executable)

The executable needs no installation and no Python. Download `investigation.exe` and
`investigation.exe.sha256` from the [latest release](https://github.com/baranaktas/dfir_investigation/releases/latest)
and put them in any folder on the host or on an external drive.

An external drive is not required, but it is recommended:

| What you collect | Output on the host's own disk | External drive |
|---|---|---|
| Live data, files, shadow copies | Works; the tool warns that writing to the system drive changes the evidence disk | Recommended |
| Memory image | Works if there is enough free space (about the size of the RAM) | Recommended |
| Disk image | Not possible for the disk that holds the output; the tool refuses it | Required for imaging the system disk |

FAT32 cannot hold files larger than 4 GB, so an external drive for memory or disk images must be exFAT or
NTFS.

**Using the menu:** double-click `investigation.exe` and accept the administrator prompt.

```
+----------------------------------------+
| Investigation 0.1.0                    |
| Host:    WS-0142                       |
| Admin:   yes                           |
| Output:  E:\                           |
+----------------------------------------+

 EVIDENCE
  1  Collect evidence     live data, files, memory, disk image
  2  Analyze              examine a package, build the HTML report

 TOOLS
  3  Verify a package     re-check all hashes
  4  Environment check    what is installed / missing
  5  Update Sigma rules   download rules (internet)

  0  Exit
```

Choose **1** to collect. Choose **2** to analyze a package; when the analysis finishes, the menu offers to
open the report. By default, packages and reports are written to the folder that contains the executable.

**Using PowerShell:** open PowerShell as administrator (right-click the Start button and choose "Terminal (Admin)" on
Windows 11 or "Windows PowerShell (Admin)" on Windows 10) and change to the folder that holds the executable,
here the external drive `E:`.

```powershell
cd E:\

# Compare with the value in investigation.exe.sha256
(Get-FileHash .\investigation.exe -Algorithm SHA256).Hash
Get-Content .\investigation.exe.sha256

.\investigation.exe --version
.\investigation.exe doctor                 # environment and module check
.\investigation.exe collect -o E:\         # interactive collection dialogue
.\investigation.exe analyze E:\INV_<HOST>_<UTC time> --case 2026-014
.\investigation.exe menu                   # the same menu as a double-click
```

Without `-o`, the report folder is created in the current directory, here
`E:\INV_<HOST>_<UTC time>_report\`. Open `report.html` in it with a browser.

Windows SmartScreen may show "Windows protected your PC" because the executable is not code-signed. Check the
SHA-256 first, then choose "More info" and "Run anyway".

## Installing from source

Needed to analyze on macOS or Linux, to use your own modules, or to work on the code. Python 3.12 or 3.13 is
required; 3.14 does not work yet because yara-python has no build for it.

### Windows (PowerShell)

1. Install 64-bit Python 3.12 from python.org, for example
   [3.12.10](https://www.python.org/downloads/release/python-31210/) ("Windows installer (64-bit)"), and Git
   from [git-scm.com](https://git-scm.com/download/win).
2. In PowerShell:

```powershell
git clone https://github.com/baranaktas/dfir_investigation.git
cd dfir_investigation
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -e .
.venv\Scripts\investigation.exe doctor
```

3. Run commands with `.venv\Scripts\investigation.exe`, for example
   `.venv\Scripts\investigation.exe analyze C:\Cases\INV_WS-0142_20261126T101500Z`. Collection needs an
   administrator PowerShell.

### macOS and Linux

Install Python 3.12 or 3.13 (macOS: `brew install python@3.12`; Ubuntu 24.04: `sudo apt install python3
python3-venv git`, which provides Python 3.12), then:

```bash
git clone https://github.com/baranaktas/dfir_investigation.git
cd dfir_investigation
python3.12 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .
.venv/bin/investigation doctor
.venv/bin/investigation analyze /cases/INV_WS-0142_20261126T101500Z
```

On Ubuntu, use `python3` instead of `python3.12` if `python3 --version` shows 3.12.

### Notes

- When run from source, `analyze` installs a missing required Python package with pip before it starts; pass
  `--no-install` to prevent that. The executable never installs anything.
- For the test suite, install the development extra: `pip install -e ".[dev]"`, then `pytest -q`.
- To build the executable yourself, see [docs/BUILD.md](docs/BUILD.md).

## Collecting evidence

The collection dialogue asks one question per category, then for drives and the output folder, and shows a
summary before anything runs. An example with every category selected:

```
Live data (processes, network, services...)? [Y/n] y
Files (registry, event logs, $MFT, Prefetch...)? [Y/n] y
Memory image (~16 GB, loads the WinPmem driver temporarily)? [Y/n] y
Shadow copies? [y/N] y
Disk image (raw copy of whole disks, not onto the output disk)? [y/N] y
Drives on this machine:
  C:   512 GB  NTFS  (system)
  E:  1000 GB  exFAT  "IR-KIT"  (output)
Collect files from which drives? (Enter = C:, e.g. C,T, or 'skip')
Image which drives? (e.g. T, Enter = skip) C
Disk image size: ~512 GB
Output folder [E:\]  (free: 990 GB on E:)
  Tip: use an external/USB drive, e.g. E:\
>

Will collect: live, files, memory, vss, disk
Files from: C:
Disk image of: C:
Output: E:\
Start? [Y/n]
```

Drives can be given as letters (`D`, `D:`) or volume labels. `skip` (or `none`, `-`, `n`) leaves out the
files or the disk image part. When the output folder is on a disk that is to be imaged, or has less free
space than the estimated size, the dialogue warns and asks again.

Collectors run in this order: memory image, live data, files, shadow copies, disk images.

The console shows progress while it works, at most one line every two seconds per step: the step number
(`[2/4] files_raw ...`), file and byte counts, the memory image percentage and, during analysis, the module
being parsed and its event count. Progress is not written to `collection.log`.

If shadow copies are selected and the output folder is on a drive whose shadow copies are collected, the
dialogue warns that writing there can make Windows delete its oldest shadow copies and asks for
confirmation. Use an external drive for the output.

When the collection ends, the dialogue asks "Compress the package into a zip?". On the command line use
`--zip`. The zip is written next to the package folder as `<package>.zip`, with `<package>.zip.sha256`; the
folder is kept. The tool checks that the drive has room for it first.

### Categories

| Category | What is collected |
|---|---|
| Live data | 21 collectors: system information, processes (with SHA-256 and Authenticode signature status), network connections with the owning process, DNS cache, ARP table, routes, services, drivers, loaded DLLs per process, scheduled tasks, named pipes, logon sessions, user sessions, SMB shares, SMB sessions, firewall rules, WMI event subscriptions, Microsoft Defender status and exclusions, environment variables, installed hotfixes, clipboard text |
| Files | Read from the raw NTFS volume, so locked files can be copied, and stored in KAPE layout: `$MFT`, `$LogFile`, `$UsnJrnl:$J`, `$Secure:$SDS`, system and user registry hives, Amcache, event logs, Prefetch, SRUM, PCA, Windows Timeline, LNK files and Jump Lists, Explorer caches, PowerShell history, Chromium and Firefox profiles, scheduled tasks, startup folders, WMI repository, hosts file, RDP bitmap cache, Defender logs, `setupapi.dev.log`, Recycle Bin `$I` files, IIS logs. The full list is in `investigation/artifacts/collect_targets.yaml` |
| Memory image | WinPmem, raw format (x64 hosts only) |
| Shadow copies | The same files from every existing volume shadow copy of the selected drives. A file that is identical to the copy under `files/` is not stored again: the manifest lists it with `same_as` pointing at the stored copy |
| Disk image | Raw (`.dd`) copy of the physical disks behind the selected drives. MD5, SHA-1 and SHA-256 are computed while copying; unreadable ranges are logged |

The same from an elevated command prompt:

```powershell
investigation.exe collect -o E:\                                   # interactive dialogue
investigation.exe collect --all --yes -o E:\ --case 2026-014       # all categories except the disk image
investigation.exe collect --only live,files --drives C,D -o E:\
investigation.exe collect --only files --disk-image --image-drives D -o E:\
investigation.exe collect --only processes,network -o E:\          # single collectors by name
investigation.exe collect --all --yes -o E:\ --zip                 # also compress the package at the end
```

### Package layout

```
INV_<HOST>_<UTC time>/
├── manifest.json        status, collector results and timings, case and examiner, SHA-256 of every file
├── collection.log
├── volatile/            processes.csv, network.csv, services.csv, tasks.csv, dns_cache.csv, ...
├── files/C/...          collected files in KAPE layout
├── vss/<n>/C/...        files from shadow copy <n> that differ from files/C/ (identical ones are only listed in the manifest)
├── memory/memory.raw
└── disk/PhysicalDrive0.dd
```

The package status is `complete`, `partial` (a collector failed or was skipped) or `aborted` (interrupted
with Ctrl+C). To check a package after copying it:

```powershell
investigation.exe verify E:\INV_WS-0142_20261126T101500Z
```

`verify` re-hashes every file, including disk images, and exits with 0 when everything matches. It also
accepts the `.zip` (and checks it against its `.sha256` file when that is next to it). `analyze` accepts the
zip as well.

## Analyzing evidence

```bash
investigation analyze INV_WS-0142_20261126T101500Z --case 2026-014 --examiner "J. Doe"
investigation analyze disk.E01 --memory mem.raw --ioc iocs.txt
investigation analyze C:\KAPE\output
investigation analyze memory.raw --profile memory
```

| Input | Notes |
|---|---|
| Investigation collection package | The manifest is checked first; mismatches are reported, not fatal. Disk images inside the package are not re-hashed (use `verify`) and not analyzed automatically; analyze them as a separate input |
| Disk images and VM disks | Through dissect.target: E01/Ex01, raw/dd/img/001, VMDK, VHD, VHDX, QCOW2, VDI. Differencing (child) disks must be merged first |
| KAPE output (folder or VHDX), zip or tar collections | Through dissect.target |
| A mounted or copied Windows system folder (`C:\` layout) | Through dissect.target |
| Any other folder (for example a copied `winevt\Logs`) | Files are found by name and extension |
| Memory image (`.raw`, `.mem`, `.vmem`, `.dmp`, `.lime`) | Volatility 3; can also be added to another input with `--memory` |

Output, by default in `<input name>_report/` in the current directory (choose another folder with `-o`):

| File | Content |
|---|---|
| `report.html` | The report, a single file without external resources |
| `timeline.csv` | All events |
| `commands.csv` | Every command found, with source, user, process and the suspicious-command rule IDs |
| `events.jsonl` | All events with every parsed field |
| `findings.json` | Findings with rule ID, severity, ATT&CK techniques and the matching events |
| `stories.json` | File stories |
| `investigation.db` | SQLite database of the events |

Exit codes: `0` success, `1` finished but a module was skipped or failed (listed in the report), `2` input
or usage error.

### Profiles

Profiles choose which modules run. They are a command-line option (`--profile`); the menu does not ask and
always uses `full`.

| Profile | Contents |
|---|---|
| `full` (default) | All modules |
| `triage` | All modules except $MFT, $UsnJrnl, thumbcache and MPLog |
| `ransomware` | Execution, persistence, backup deletion, file-system activity, network volume |
| `lateral-movement` | Logons, RDP in and out, remote services and tasks, WMI, network history |
| `memory` | Volatility 3 analysis and the memory detections |

`investigation profiles show <name>` lists the modules of a profile. Your own profiles go in
`~/.investigation/profiles/*.yaml`.

## The report

`report.html` opens in any browser and contains:

- **Summary bar**: number of events, number of findings per severity, number of events per source.
- **Findings**, grouped by ATT&CK tactic in kill-chain order (findings without a technique go under
  "Other"). Each finding shows its severity, rule ID, ATT&CK techniques, description, an analyst note and up
  to 50 of its events; all events are in `findings.json`.
- **Commands**: every command run, from PowerShell history, Security 4688, Sysmon 1, PowerShell 4103 and
  4104, live processes, memory command lines and console history, and RunMRU. Rows are sorted by time (rows
  without a time, such as PowerShell history, come last grouped by file), can be filtered with the filter
  box, and commands matching a suspicious pattern carry a "suspicious" badge. Long script blocks show the
  first 300 characters with the rest expandable; `commands.csv` has the full text. cmd.exe history exists
  only in memory images (Volatility `cmdscan` and `consoles`); Windows does not log it otherwise.
- **Timeline**: the events around the findings first, then the rest. Up to 200,000 events are embedded in
  the page; the complete timeline is in `timeline.csv` and `investigation.db`.
- **File stories**: for each executable named in a finding, the events that mention it, grouped into where
  it came from, when it ran, who ran it, whether it persisted and what it touched, plus its hashes when known.
- **Interpretation notes**: for each artifact that produced events, what it proves and what it does not (for
  example: on Windows 10 and later a Shimcache entry does not prove execution).
- **Technical details**: the input, the package's host name, status and tool version, event counts per
  artifact and per evidence type, preflight checks and module errors.

Every section can be collapsed, and a filter box searches the findings and the open timeline groups. Text
from the evidence is inserted as plain text, never as HTML.

## What is parsed

50 parser modules. `investigation modules list --type parser` prints them all.

| Category | Artifacts |
|---|---|
| Execution | Prefetch, BAM, UserAssist, Amcache (applications and files), Shimcache, SRUM application usage, StartupInfo, PowerShell history |
| Files and folders | LNK files, Jump Lists (automatic and custom), ShellBags, RecentDocs, OpenSave and LastVisited MRU, Office MRU, Trusted Documents, Thumbcache |
| User activity | Windows Timeline (ActivitiesCache), RunMRU, WordWheelQuery, TypedPaths, search MRU |
| File system | `$MFT`, `$UsnJrnl:$J`, Recycle Bin |
| Persistence | Run keys, services, scheduled tasks, WMI event subscriptions, AppInit DLLs, cmd AutoRun, Winlogon shell |
| Devices and network | USB devices, network profiles, SRUM network usage, outgoing RDP connections, RDP bitmap cache, browser history and downloads, IIS logs |
| Defense and accounts | Defender exclusions, quarantine and MPLog, local SAM accounts (password hashes are dropped) |
| Event logs | All `.evtx` files |
| Live data | The CSV files of a collection package |
| Memory | Volatility 3 `pslist`, `psscan`, `cmdline`, `cmdscan`, `consoles`, `netscan`, `malfind`, `svcscan` |
| YARA | Matches of the YARA scan (see below) |

## Detection

| Engine | What it does | Rules |
|---|---|---|
| Built-in rules | 58 YAML rules over event logs, artifacts and memory, plus 9 command rules over every command source, with threshold, distinct-count and sequence correlation | `investigation/rules/builtin/`; your own in `~/.investigation/rules/*.yaml` |
| Sigma | SigmaHQ rules evaluated against the parsed event logs; Security 4688 events are also matched against process-creation rules | Not included: run `investigation rules update` (internet) or `--from-zip` (offline). Your own in `~/.investigation/rules/sigma/` |
| YARA | Scans Temp, Downloads, Desktop, Public, ProgramData, web roots and the Recycle Bin | 7 built-in rules (PHP, ASPX and JSP web shells, Mimikatz, Cobalt Strike, PowerShell download cradles, ransom notes); your own in `~/.investigation/rules/yara/` |
| IOC | Hashes, IP addresses, domains (including subdomains), URLs and file names anywhere in the timeline; defanged input accepted | `--ioc list.txt` (repeatable) or `~/.investigation/ioc/*.txt` |
| Live data | Unsigned process running from a user-writable path; living-off-the-land binary with an internet connection; WMI consumer that runs commands or scripts; Microsoft Defender weakened | Built-in |
| Process tree | Unexpected parents of system processes, a second `lsass.exe`, children of LSASS, processes found by `psscan` but missing from `pslist` | Built-in |

Rules can produce false positives (administration tools behave like attackers) and miss techniques they do
not cover. Treat findings as leads to verify, not as conclusions.

## How evidence is handled

- The analyzer opens its input read-only and never writes to it. The output folder may not be inside the
  input folder.
- The collector reads files from the raw NTFS volume. Destination paths are checked to stay inside the
  package, and names that are not valid on the analysis platform are stored under an encoded name with the
  original name in the manifest.
- WinPmem is embedded in the executable. Before it runs, it is copied to a private directory under
  `%SystemRoot%\Temp` with a restricted access list and checked against a pinned SHA-256. Taking a memory
  image loads its driver temporarily: WinPmem itself extracts the driver to the user's `%TEMP%` while it loads
  it and deletes it afterwards.
- Ctrl+C stops a collection; what was collected so far is kept and listed in the manifest.
- Running the executable changes the host in ways you should document: it unpacks itself to `%TEMP%` while it
  runs, WinPmem loads a driver, and Windows itself records program execution (for example in Prefetch and
  the event logs). Keep the output on external media.

## Command-line reference

```
investigation analyze  <input> [-o OUT] [--profile NAME] [--case ID] [--examiner NAME]
                       [--ioc FILE ...] [--memory IMAGE] [--no-install] [--force]
investigation collect  [--all | --only NAMES] [--drives C,D] [--disk-image] [--image-drives T]
                       [-o OUT] [--case ID] [--examiner NAME] [--yes] [--zip]
investigation verify   <package or .zip>
investigation doctor   [--profile NAME] [--json]
investigation modules  list [--type source|parser|detection|output|collector]
investigation modules  info <name>
investigation profiles list | show <name>
investigation run      <module> <input> [-o OUT] [--force]
investigation rules    update [--url URL | --from-zip FILE]
investigation menu
```

The executable always requests administrator rights. Run command-line subcommands from an elevated prompt;
from a normal prompt Windows opens a separate elevated window that closes when the command finishes.

## Extending

Parsers, detections, outputs and sources are modules. Put a `.py` file in `~/.investigation/modules/` (or
set `INVESTIGATION_HOME`):

```python
from investigation.core.models import Event, EvidenceType
from investigation.core.module import ModuleMeta, ModuleType, ParserModule
from investigation.core.registry import register


@register
class HostsFile(ParserModule):
    meta = ModuleMeta(
        name="hosts_file",
        description="Entries in the Windows hosts file",
        type=ModuleType.PARSER,
    )

    def parse(self, source, ctx, errors):
        for path in source.glob("**/drivers/etc/hosts"):
            ...  # yield Event(...)
```

The rule format is documented at the top of `investigation/rules/builtin/evtx.yaml`. Your own modules are
loaded by the analyzer only; the collector runs built-in modules only.

## Test status

| What | Where it was tested |
|---|---|
| Automated test suite | macOS (Python 3.13); GitHub Actions on Ubuntu (Python 3.12 and 3.13) and Windows (Python 3.12.10) |
| Live data, file collection, shadow copies, disk image of a 4 GB virtual disk, analysis with the executable | Windows 11 ARM64 virtual machine, running the x64 executable under emulation |
| Event log detections | Attack samples from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) in the test suite |
| Artifact parsers, E01 image | Sample files from the [dissect.target](https://github.com/fox-it/dissect.target) test data in the test suite |
| The release executable | Built with Python 3.12.10 on GitHub Actions; the same build steps produced the executable used in the virtual machine tests |

Not tested yet:

- Memory imaging with WinPmem (the test machine was ARM64, where it is not available).
- Collection on Windows 10, Windows Server and physical x64 hardware.
- Detection rates on a labelled data set, and false-positive rates on a range of clean hosts.

Reports from real use are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Limitations

- Memory imaging needs an x64 host; WinPmem has no ARM64 driver.
- The embedded WinPmem driver (v4.0.rc1) is affected by
  [CVE-2024-10972](https://osv.dev/vulnerability/CVE-2024-10972) and
  [CVE-2024-12668](https://osv.dev/vulnerability/CVE-2024-12668). With administrator rights, each can crash
  the system or write to kernel memory while the driver is loaded. The driver is loaded only while the memory
  image is taken. The fixed driver (v4.1) is only test-signed so far, so it cannot be used on standard
  Windows. Skip the memory image if this risk is not acceptable.
- Shadow copies are read on live hosts only, not from disk images.
- Volatility 3 downloads Windows symbol tables the first time it sees an OS build. Offline analysis needs a
  prepared symbol cache.
- The executable is not code-signed. SmartScreen or antivirus software may warn about it; compare the
  SHA-256 with the release page.
- Building the executable requires Windows; see [docs/BUILD.md](docs/BUILD.md).

## License

The source code is released under the [MIT License](LICENSE). The executable on the Releases page also
contains third-party components under their own licenses, including AGPL-3.0 libraries; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Investigation is built on [dissect](https://github.com/fox-it/dissect),
[Volatility 3](https://github.com/volatilityfoundation/volatility3),
[WinPmem](https://github.com/Velocidex/WinPmem), [YARA](https://github.com/VirusTotal/yara),
[pySigma](https://github.com/SigmaHQ/pySigma) and the [SigmaHQ](https://github.com/SigmaHQ/sigma) rules.

Use it only on systems you are authorized to investigate.
