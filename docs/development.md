# Development

## Repository layout

- `src/mosec/`: Python package and CLI entry point
- `tests/`: unit and smoke tests
- `fixtures/`: sample inputs and golden outputs
- `rust/`: future Rust core workspace

## Local setup

```bash
python -m pip install -e ".[dev]"
```

## Useful commands

```bash
python -m pytest
python -m compileall src tests
mosec version
mosec scan fixtures
```

## Working guidelines

- Keep the CLI behavior backwards compatible when possible.
- Update tests when changing reports or schema.
- Prefer small, explicit data models.
- Keep public docs aligned with the command-line surface.

