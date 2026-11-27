# Contributing

Bug reports, new artifact parsers and detection rules are welcome.

## Setup

Python 3.12 or 3.13.

```bash
git clone https://github.com/baranaktas/dfir_investigation.git
cd dfir_investigation
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/pytest -q
```

## Guidelines

- One module per file. Parsers live in `investigation/modules/parsers/`, detections in
  `investigation/modules/detections/`, collectors in `investigation/modules/collectors/`.
- Every change needs a test. Use small, synthetic fixtures; never commit real case data.
- New detection rules need an ATT&CK technique ID and a short description of what the rule means for the
  analyst.
- The analyzer must never write to the evidence, and collectors must not change the host beyond what is
  documented. Changes that touch either deserve an explicit note in the pull request.
- Keep the user-facing text short and plain. Run `pytest -q` before opening a pull request.

New built-in modules must also be added to `investigation/_builtin_modules.py` so that they are included in
the executable.
