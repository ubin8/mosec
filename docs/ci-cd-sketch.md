# MoSec CI/CD Sketch

## Purpose
Document the first CI/CD shape for MoSec before the collaboration and policy details are implemented.

This sketch is intentionally narrow:
- it proves where MoSec runs in CI
- it keeps the command contract aligned with the CLI
- it leaves auth, uploads, comment bots, and PR deduplication for later backlog items

## Shared CI Principles
- Use the same `mosec scan` command in every CI provider.
- Prefer deterministic output (`json` or `sarif`) for machine consumption.
- Keep CI jobs read-only except for artifact uploads.
- Fail the pipeline when `--fail-on` is hit.
- Preserve raw outputs as artifacts for debugging and triage.

## GitHub Actions Sketch
```yaml
name: MoSec

on:
  push:
    branches: ["main"]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install MoSec
        run: python -m pip install -e ".[dev]"

      - name: Run tests
        run: python -m pytest

      - name: Run MoSec scan
        run: mosec scan . --format sarif --fail-on high

      - name: Upload SARIF
        uses: actions/upload-artifact@v4
        with:
          name: mosec-sarif
          path: ./*.sarif
```

## GitLab CI Sketch
```yaml
stages:
  - test
  - scan

variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

test:
  stage: test
  image: python:3.11
  script:
    - python -m pip install -e ".[dev]"
    - python -m pytest

mosec_scan:
  stage: scan
  image: python:3.11
  script:
    - python -m pip install -e ".[dev]"
    - mosec scan . --format json --fail-on high
  artifacts:
    when: always
    paths:
      - ./*.json
      - ./*.sarif
```

## Known Gaps
- Authentication for private repositories is not part of this sketch.
- Artifact naming and retention policy are still undecided.
- PR comment posting is handled by later backlog items.
- Dedupllication of findings in comments is handled by later backlog items.
- Policy mapping for branch-specific gating is handled later.
