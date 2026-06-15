# MoSec Analysis Platform

CLI-first MoSec analysis tool in Python, with a Rust workspace reserved for future performance-critical analysis components.

## Repo Layout

```text
.
|-- docs/                  # Roadmap, architecture, backlog
|-- src/appsec_cli/        # Python CLI and orchestration layer
|-- tests/                 # Python tests
|-- rust/                  # Rust workspace for future core analysis
`-- pyproject.toml         # Python packaging for the CLI
```

## Current Direction

- Python owns the CLI, configuration, reporting, and repo orchestration.
- Rust is reserved for parser, taint, and other compute-heavy modules later.
- The repo is structured so the Python CLI can call into Rust once the native core is ready.

## Documentation Pack

- [Foundation Pack](docs/foundation-pack.md)
- [Development Setup](docs/development-setup.md)
- [Versioning](docs/versioning.md)
- [CI/CD Sketch](docs/ci-cd-sketch.md)
- [Collaboration Sketch](docs/collaboration-sketch.md)
- [PR Comment Sketch](docs/pr-comment-sketch.md)
- [Policy Sketch](docs/policy-sketch.md)
- [False-Positive Sketch](docs/false-positive-sketch.md)
- [Audit Sketch](docs/audit-sketch.md)
- [Suppression Review Sketch](docs/suppression-review-sketch.md)
- [Manual Override Sketch](docs/manual-override-sketch.md)
- [Roadmap](docs/appsec-roadmap.md)
- [Backlog](docs/appsec-backlog.md)
- [P0 Backlog](docs/appsec-p0-backlog.md)

## Next Milestone

1. Define the CLI commands and config format.
2. Implement repository ingestion and file discovery.
3. Add first detection modules for secrets and simple rules.
4. Wire JSON and SARIF reporting.

## Local Setup

```bash
python -m pip install -e ".[dev]"
mosec version
```
