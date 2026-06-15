# MoSec

MoSec is a CLI-first application security scanner for source code, configuration files, and mobile manifests.

It is built around a Python command-line tool today, with a Rust workspace reserved for future performance-critical analysis components.

## What MoSec does

- Scans local repositories and single files from the command line
- Detects secrets, vulnerable dependencies, and common web application issues
- Understands multiple languages and frameworks
- Produces text, JSON, and SARIF reports
- Supports baseline files, suppressions, manual overrides, and policy gates
- Includes Android-focused checks for manifests and insecure storage patterns

## Quick Start

```bash
python -m pip install -e ".[dev]"
mosec version
mosec scan .
```

## Documentation

- [Documentation Index](docs/README.md)
- [Getting Started](docs/getting-started.md)
- [CLI Reference](docs/cli-reference.md)
- [Configuration](docs/configuration.md)
- [Analysis Model](docs/analysis-model.md)
- [Rules and Findings](docs/rules-and-findings.md)
- [Reporting and CI Usage](docs/reporting.md)
- [Mobile Analysis](docs/mobile-analysis.md)
- [Development](docs/development.md)
- [Troubleshooting](docs/troubleshooting.md)

## Repository Layout

```text
.
|-- docs/           # Public user and developer documentation
|-- src/mosec/      # Python CLI and analysis orchestration layer
|-- tests/          # Test suite
|-- fixtures/       # Scan fixtures and golden outputs
|-- rust/           # Future Rust core workspace
`-- pyproject.toml  # Python packaging metadata
```

## Current Scope

- Python owns the CLI, configuration, reporting, and repository orchestration.
- Rust is reserved for parser, taint, and other compute-heavy modules later.
- The current release focuses on local scanning and CI-friendly output.

## Versioning

MoSec follows semantic versioning for the CLI package. See [docs/versioning.md](docs/versioning.md).
