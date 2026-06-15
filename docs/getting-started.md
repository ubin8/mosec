# Getting Started

## Requirements

- Python 3.11 or newer
- A local checkout of the repository or an installed wheel

## Install for development

```bash
python -m pip install -e ".[dev]"
```

## Verify the install

```bash
mosec
mosec version
```

## Open the terminal home screen

```bash
mosec
```

## Use the interactive shell

The interactive shell is command-driven. Start with:

```bash
/help
```

Common scan commands:

```bash
/scan
/scan-quick
/scan-deep
/scan-web
/scan-mobile
```

## Run a scan from the CLI

The CLI remains available for automation and non-interactive use:

```bash
mosec scan .
mosec scan . --format json
mosec scan . --format sarif
mosec scan . --config fixtures/config/mosec.toml
```

## What to expect

- `mosec` without arguments opens the terminal home screen
- the home screen is the entry point to the command-driven TUI
- exact slash commands such as `/scan` and `/scan-quick` drive interactive workflows
- `--format json` emits the full machine-readable report
- `--format sarif` emits SARIF for code hosts and CI pipelines
