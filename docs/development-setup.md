# MoSec Development Setup

## Purpose
Document the minimal local setup needed to develop and run MoSec.

## Runtime Requirements
- Python 3.11 or newer.
- `pip` for editable installs.
- `pytest` for the local test suite if you want to run the Python tests.
- Rust is optional for the current Python-first stage.

## Install
```bash
python -m pip install -e ".[dev]"
```

## Verify
```bash
mosec version
python -m appsec_cli version
python3 -m compileall src tests
```

## Notes
- The command-line entry point is `mosec`.
- The Python module entry point remains available during the current skeleton phase.
- The Rust workspace is present but not required for day-to-day development yet.
