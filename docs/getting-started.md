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

## Run a scan

```bash
mosec scan .
```

## Open the terminal home screen

```bash
mosec
```

## Choose an output format

```bash
mosec scan . --format json
mosec scan . --format sarif
```

## Use a config file

```bash
mosec scan . --config fixtures/config/mosec.toml
```

## What to expect

- `mosec scan` prints a human-readable summary by default
- `mosec` without arguments opens the terminal home screen
- `--format json` emits the full machine-readable report
- `--format sarif` emits SARIF for code hosts and CI pipelines
