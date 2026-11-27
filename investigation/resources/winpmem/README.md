# Embedded WinPmem

- Source: https://github.com/Velocidex/WinPmem
- Release tag: v4.0.rc1 (latest release that ships an x64 "mini" binary)
- Asset: winpmem_mini_x64_rc2.exe
- URL: https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x64_rc2.exe
- sha256: a4d516b6fcaf3b5b1d4ee709ce86f8eabf1d8028b3a83101479b7568b933d21b
- License: Apache-2.0

The .exe is not committed. Run `python scripts/fetch_winpmem.py` on a build machine; it verifies the pinned sha256.
The collector never downloads anything; it refuses a binary whose sha256 differs from the pin.
