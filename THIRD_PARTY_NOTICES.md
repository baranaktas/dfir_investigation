# Third-party notices

The source code in this repository is released under the [MIT License](LICENSE).

The prebuilt `investigation.exe` published on the Releases page bundles the Python runtime and the
third-party components listed below. Each component remains under its own license. Because several
bundled components are licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**, the
executable as a whole is distributed under the terms of the AGPL-3.0. The complete corresponding source
code is this repository at the release tag together with the upstream projects linked below; the exact
package versions used for each build are listed in `build-requirements.txt`, attached to every release.

If you only use the Python package from source, you install these dependencies yourself and their licenses
apply to them as usual; the MIT license of this project is not affected.

## Components of the executable

The build environment contains the packages below; PyInstaller includes the parts the program imports.

| Component | License | Project |
|---|---|---|
| Python 3.12 | PSF-2.0 | https://www.python.org/ |
| dissect.target, dissect.ntfs, dissect.regf, dissect.eventlog, dissect.evidence, dissect.volume, dissect.hypervisor, dissect.archive, dissect.cim, dissect.executable, dissect.fat, dissect.fve, dissect.ole, dissect.shellitem, dissect.thumbcache | AGPL-3.0-or-later | https://github.com/fox-it/dissect |
| flow.record | AGPL-3.0-or-later | https://github.com/fox-it/flow.record |
| dissect.cstruct, dissect.util, dissect.database | Apache-2.0 | https://github.com/fox-it/dissect |
| Volatility 3 | Volatility Software License 1.0 | https://github.com/volatilityfoundation/volatility3 |
| WinPmem (`winpmem_mini_x64_rc2.exe`) | Apache-2.0 | https://github.com/Velocidex/WinPmem |
| yara-python / libyara | Apache-2.0 / BSD-3-Clause | https://github.com/VirusTotal/yara-python |
| pySigma | LGPL-2.1-only | https://github.com/SigmaHQ/pySigma |
| SigmaHQ core Windows rules, release r2026-07-01 (`sigma_core.zip`, the rules are attributed to the SigmaHQ authors) | Detection Rule License 1.1 | https://github.com/SigmaHQ/sigma, https://github.com/SigmaHQ/Detection-Rule-License |
| psutil | BSD-3-Clause | https://github.com/giampaolo/psutil |
| pywin32 | PSF-2.0 | https://github.com/mhammond/pywin32 |
| Jinja2, MarkupSafe | BSD-3-Clause | https://palletsprojects.com/ |
| PyYAML | MIT | https://github.com/yaml/pyyaml |
| pycryptodome | BSD-2-Clause, Unlicense | https://github.com/Legrandin/pycryptodome |
| pefile | MIT | https://github.com/erocarrera/pefile |
| google-re2 | BSD-3-Clause | https://github.com/google/re2 |
| jq | BSD-2-Clause | https://github.com/mwilliamson/jq.py |
| msgpack | Apache-2.0 | https://github.com/msgpack/msgpack-python |
| structlog | MIT or Apache-2.0 | https://github.com/hynek/structlog |
| pyparsing | MIT | https://github.com/pyparsing/pyparsing |
| requests, urllib3, idna, charset-normalizer, certifi | Apache-2.0, MIT, BSD-3-Clause, MIT, MPL-2.0 | https://github.com/psf/requests |
| defusedxml | PSF-2.0 | https://github.com/tiran/defusedxml |
| diskcache | Apache-2.0 | https://github.com/grantjenks/python-diskcache |
| PyInstaller bootloader | GPL-2.0 with the PyInstaller bootloader exception | https://github.com/pyinstaller/pyinstaller |

The full license texts are included in each upstream project and in the `*.dist-info` folders of an
installed environment.

## Rules and test data

| Material | License | Source |
|---|---|---|
| `tests/fixtures/sigma/*.yml` (a few SigmaHQ rules used in tests) | Detection Rule License 1.1 | https://github.com/SigmaHQ/sigma |
| `tests/fixtures/evtx/*.evtx` (unmodified attack samples used in tests) | GPL-3.0 | https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES |
| `tests/fixtures/windows/*` (unmodified artifact samples used in tests) | AGPL-3.0 | https://github.com/fox-it/dissect.target |
