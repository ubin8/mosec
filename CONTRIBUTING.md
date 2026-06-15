# Contributing

Thanks for improving MoSec.

## Before you change code

- Keep the public docs and the CLI surface in sync.
- Prefer small, reviewable changes.
- Add or update tests for behavior changes.

## Local workflow

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m compileall src tests
```

## Pull request expectations

- Explain what changed and why.
- Mention any new flags, output fields, or rule behavior.
- Include sample output when changing reports or user-facing docs.

