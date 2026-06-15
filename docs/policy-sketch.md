# MoSec Policy Sketch

## Purpose
Define the first policy gate shape for MoSec scans.

This sketch covers:
- blocking rules for critical and high findings
- warning rules for medium findings
- project-wide overrides
- branch-specific rules
- storing the final policy decision in the report

## Policy Levels
- `critical`: always block by default
- `high`: block by default
- `medium`: warn by default, do not block unless explicitly configured
- `low`: informational by default
- `info`: informational only

## Default Block Rules
- Critical findings block the scan.
- High findings block the scan.
- Medium findings should not block by default.
- Low and info findings should never block by default.

## Warning Rules
- Medium findings should be listed prominently as warnings.
- Warnings should not fail the scan unless the configured threshold says otherwise.
- Warnings should remain visible in JSON, SARIF, and text output.

## Project-Wide Overrides
- A project may set a stricter or looser threshold than the default.
- Project overrides should come from configuration, not from the scanner code itself.
- Overrides should be explicit and auditable.

## Branch-Specific Rules
- Protected branches may use stricter thresholds than feature branches.
- Branch rules are supplied through config as exact branch names.
- The current branch is supplied at scan time and matched against the configured overrides.
- Branch overrides are evaluated before the scan result is turned into an exit code.
- Explicit CLI `--fail-on` values win over branch-specific overrides.

Example config shape:
```toml
fail_on = "high"

[branch_fail_on]
main = "critical"
release = "high"
```

## Policy Decision In Report
- The report should store:
  - configured threshold
  - final decision
  - whether the scan is blocking
- The decision should be stable and machine-readable.
- The decision should be visible in JSON and SARIF properties.

## Known Gaps
- Policy expressions beyond simple severity thresholds are not defined yet.
- Branch-aware runtime logic is not implemented yet.
- Per-path or per-rule policy exceptions are not defined yet.
