Download `investigation.exe`, copy it to an external drive and double-click it on the host you investigate.
Verify the file against `investigation.exe.sha256` before use:

```powershell
(Get-FileHash .\investigation.exe -Algorithm SHA256).Hash
```

The executable is built for x64 Windows, asks for administrator rights when started and does not need Python
or an internet connection on the host. `build-requirements.txt` lists the exact package versions it contains. See the [README](https://github.com/baranaktas/dfir_investigation#readme) for usage and
[CHANGELOG.md](https://github.com/baranaktas/dfir_investigation/blob/main/CHANGELOG.md) for what changed.

The executable bundles third-party components, including AGPL-3.0 libraries; see
[THIRD_PARTY_NOTICES.md](https://github.com/baranaktas/dfir_investigation/blob/main/THIRD_PARTY_NOTICES.md).
