# Building investigation.exe

This guide produces the single-file `investigation.exe` from source. Release builds are made automatically
by GitHub Actions (`.github/workflows/release.yml`); build locally only if you changed the code or want to
verify a release.

The executable is always built for **x64**, which is what you meet on real incident hosts. ARM64 Windows
runs x64 programs under emulation, so building on an ARM64 machine (for example a VM on Apple silicon)
works too.

## 1. Requirements

| What | Notes |
|---|---|
| Windows (x64 or ARM64) | Tested on a Windows 11 ARM64 VM and on the GitHub Actions `windows-latest` runner |
| **x64** Python 3.12 | python.org, "Windows installer (64-bit)", not the ARM64 installer and not the Microsoft Store build |
| Internet access | Only during the build: Python packages and WinPmem are downloaded |

Silent install into a separate folder (elevated PowerShell; does not touch any other Python):

```powershell
Invoke-WebRequest https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe -OutFile $env:TEMP\py312x64.exe
Start-Process $env:TEMP\py312x64.exe -Wait -ArgumentList "/quiet InstallAllUsers=1 TargetDir=C:\Python312x64 PrependPath=0 Include_launcher=0 Include_test=0"
C:\Python312x64\python.exe -c "import sysconfig; print(sysconfig.get_platform())"
```

The last command must print `win-amd64`.

## 2. Get the source

```powershell
git clone https://github.com/baranaktas/dfir_investigation.git
cd dfir_investigation
```

Or download the source zip from the Releases page and extract it.

## 3. Build

From an **elevated** PowerShell in the repository folder:

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build_exe.ps1 -Python C:\Python312x64\python.exe
```

Without `-Python` the script tries `py -V:3.12-64`, then `python3.12`, then `python`.

The script stops at the first failing step:

1. Checks that the interpreter is an x64 build (`sysconfig.get_platform() == "win-amd64"`).
2. Creates a fresh virtual environment in `build\venv` and installs the project with the `build` extra
   (PyInstaller included).
3. Downloads WinPmem and verifies it against the pinned SHA-256 (`scripts/fetch_winpmem.py`). An existing
   file with the right hash is reused.
4. Downloads the pinned SigmaHQ rule release and verifies its SHA-256 (`scripts/fetch_sigma.py`), keeping the
   Windows rules in `investigation\resources\sigma\`.
5. Runs PyInstaller on `packaging/investigation.spec` and writes `dist\investigation.exe`.
6. Smoke-tests the result with `--version` and `doctor`, then prints the executable's SHA-256.

PyInstaller prints many `WARNING: Library not found`
lines for Windows system DLLs (`VERSION.dll`, `bcrypt.dll`, `ntdll.dll`, ...) and some
`Hidden import 'volatility3.plugins...' not found` lines. Neither stops the build: system DLLs are present
on every Windows installation and are intentionally not bundled.

## 4. What a good build looks like

The end of the `doctor` output:

```
    [OK]       dissect plugins: <number> loaded
63 module(s) ready, 0 skipped.
```

followed by `Algorithm : SHA256` and the hash. The number of dissect plugins depends on the dissect version
but must not be 0. A `[WARN]` about missing Sigma rules is expected; rules are downloaded at run time with
`investigation rules update`.

## 5. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `x64 Python required (got 'win-arm64')` | ARM64 or Store Python | Install x64 Python as in section 1 and pass `-Python` |
| `fetch_winpmem failed ... CERTIFICATE_VERIFY_FAILED` | Missing root certificates on a fresh Windows | The script uses certifi; if it still fails, download the file manually into `investigation\resources\winpmem\` (name and SHA-256 in that folder's README) |
| `doctor` reports `dissect plugins: 0 loaded` | Plugin files missing from the bundle | Check the `collect_submodules` / data entries in `packaging/investigation.spec` |
| Analysis finds almost no events and logs `Failed to find OS plugin` | Executable built from an outdated spec | Rebuild from the current source |

## 6. Testing the executable

```powershell
.\dist\investigation.exe doctor
.\dist\investigation.exe collect --all --out C:\IR --case TEST --yes
$p = (Get-ChildItem C:\IR -Directory -Filter INV_* | Sort-Object Name | Select-Object -Last 1).FullName
.\dist\investigation.exe analyze $p -o C:\IR\report --force
```

On ARM64 machines the memory collector is skipped (WinPmem has no ARM64 driver); memory images can only be
taken on x64 hosts.

## Running the test suite

```bash
python3.12 -m venv .venv                  # Windows: py -3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'   # Windows: .venv\Scripts\python.exe -m pip install -e .[dev]
.venv/bin/pytest -q
```

Windows-only tests are skipped on other platforms.
