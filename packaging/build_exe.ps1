param([string]$Python = "")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Assert-Ok($step) {
    if ($LASTEXITCODE -ne 0) { throw "$step failed (exit code $LASTEXITCODE)" }
}

$py = $null
if ($Python) {
    $py = @($Python)
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $py = @("py", "-V:3.12-64")
} elseif (Get-Command python3.12 -ErrorAction SilentlyContinue) {
    $py = @("python3.12")
} else {
    $py = @("python")
}
$rest = @($py | Select-Object -Skip 1)
$arch = & $py[0] @rest -c "import sysconfig; print(sysconfig.get_platform())"
Assert-Ok "Python architecture check"
if ($arch.Trim() -ne "win-amd64") { throw "x64 Python required (got '$arch'). Install 64-bit (x64) Python 3.12." }

$venv = Join-Path $root "build\venv"
if (Test-Path $venv) { Remove-Item -Recurse -Force $venv }
& $py[0] @rest -m venv $venv
Assert-Ok "venv creation"
$vpy = Join-Path $venv "Scripts\python.exe"
$archv = & $vpy -c "import sysconfig; print(sysconfig.get_platform())"
Assert-Ok "venv architecture check"
if ($archv.Trim() -ne "win-amd64") { throw "build venv is not x64 ('$archv')" }

& $vpy -m pip install --upgrade pip
Assert-Ok "pip upgrade"
& $vpy -m pip install -e ".[build]"
Assert-Ok "pip install"
& $vpy scripts\fetch_winpmem.py
Assert-Ok "fetch_winpmem"
& $vpy -m PyInstaller packaging\investigation.spec --clean --noconfirm
Assert-Ok "PyInstaller"

$exe = Join-Path $root "dist\investigation.exe"
if (-not (Test-Path $exe)) { throw "dist\investigation.exe was not produced" }
& $exe --version
Assert-Ok "investigation.exe --version"
& $exe doctor
if ($LASTEXITCODE -ge 2) { throw "investigation.exe doctor failed (exit code $LASTEXITCODE)" }
Get-FileHash $exe -Algorithm SHA256 | Format-List
