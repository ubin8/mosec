# MoSec CLI Contract

## Purpose
Define the command-line surface for the first MoSec CLI release.

This contract is intentionally narrow: it captures the behavior that must exist before repository ingestion and analysis logic are implemented.

## Public Commands
```text
mosec scan <path> [options]
mosec version
```

## Command Responsibilities
### `scan`
Scan a local repository or a single file path and emit findings.

The command must:
- accept a path
- respect config and CLI filters
- produce deterministic output
- continue past file-level errors where possible
- support developer-friendly text output and machine-readable output

### `version`
Print the installed CLI version.

This command must not require any scan configuration or repository path.

## Flags
### Global Flags
- `--config <file>`: load scan defaults from a TOML file
- `--verbose`: increase diagnostic output
- `--quiet`: reduce non-essential output

### `scan` Flags
- `--format text|json|sarif`
- `--include <pattern>`: include paths matching the pattern
- `--exclude <pattern>`: exclude paths matching the pattern
- `--baseline <file>`: load baseline findings from a file
- `--suppressions <file>`: load suppression rules from a file
- `--overrides <file>`: load manual override rules from a file
- `--fail-on <severity>`: fail the process at or above a severity threshold
- `--branch <name>`: label the scan with the current branch for branch-specific policy rules

### Flag Rules
- `--format` defaults to `text`.
- `--config` is optional.
- `--include` and `--exclude` may be repeated.
- `--baseline` is optional.
- `--suppressions` is optional.
- `--overrides` is optional.
- `--fail-on` accepts `low`, `medium`, `high`, or `critical`.
- `--verbose` and `--quiet` must be mutually exclusive in practice.

## Config File Contract
The config file must be TOML and use the same precedence rules as the CLI.

Minimum supported shape:
```toml
root = "."
format = "text"
include = ["src/**"]
exclude = ["tests/**", "**/dist/**"]
baseline = "fixtures/baseline/baseline.json"
suppressions = "fixtures/suppressions/suppressions.json"
overrides = "fixtures/overrides/manual-overrides.json"
fail_on = "high"
verbose = false
quiet = false

[branch_fail_on]
main = "critical"
release = "high"
```

Config file rules:
- `root` is optional if the CLI path is provided.
- `format` must be one of `text`, `json`, or `sarif`.
- `include` and `exclude` must be arrays of strings.
- `baseline` must point to a readable file if provided.
- `suppressions` must point to a readable file if provided.
- `overrides` must point to a readable file if provided.
- `branch_fail_on` is optional and maps exact branch names to severity thresholds.
- unknown keys are allowed only if explicitly namespaced for future extensions.

## Precedence Rules
1. Explicit CLI flags win.
2. Config file values come next.
3. Built-in defaults are the fallback.
4. Branch-specific policy overrides apply when no explicit `--fail-on` threshold is set.

Examples:
- If `--format json` is set on the CLI, it overrides the config file.
- If `--exclude` is provided on the CLI, it extends or overrides default excludes depending on the implementation contract of the filter layer.
- If both config and CLI define `include`, the implementation must apply the combined filter rules in a deterministic way and document the merge behavior.
- If a branch-specific threshold exists in the config file, it overrides the configured threshold unless `--fail-on` is set explicitly on the CLI.
- Manual override rules take precedence over baseline and suppression rules.

## Exit Codes
- `0`: scan succeeded and no blocking findings were emitted
- `1`: scan succeeded, but policy gates failed
- `2`: invalid usage, invalid config, unsupported path, or unsupported format
- `3`: internal failure, unhandled exception, or unrecoverable runtime error

## Exit Code Triggers
- `0` when the scan completed and all findings stayed below the `--fail-on` threshold.
- `1` when the scan completed and at least one finding met or exceeded the failure threshold.
- `2` when argument parsing, config loading, path validation, or output selection failed.
- `3` when an unexpected runtime error occurred outside normal user or input errors.

## Output Contracts
### Text
- Intended for local developer consumption.
- Must include a short scan summary.
- Must include a findings summary grouped by severity.
- Must remain human-readable even when no findings exist.

### JSON
- Canonical machine format for tests, CI, and downstream tooling.
- Must serialize scan metadata, findings, notes, and stats.
- Must use stable field names.
- Must remain compatible with the shared data schema in `docs/data-schema.md`.

### SARIF
- Export format for code hosts and security tooling.
- Must preserve rule id, severity, location, and remediation context.
- Must remain schema-compatible with the scanner data model.
- Must map one scanner finding to one SARIF result entry.

## Output Field Rules
- Text output must always include the scanned root and finding count.
- JSON output must include `root`, `stats`, `notes`, and `findings`.
- SARIF output must include rule metadata, file location, and remediation text when present.
- Output ordering must be deterministic for identical inputs.

## Error Behavior
- Missing paths must fail with a clear user-facing error.
- Unsupported output formats must fail before scanning begins.
- File-level parse or read failures must be reported and not necessarily abort the entire scan.
- The command should return partial results if a scan can continue safely.

## Scan Flow Contract
1. Parse CLI arguments.
2. Load config if provided.
3. Build scan context from CLI and config.
4. Select input files.
5. Run detectors.
6. Apply baseline and suppression rules.
7. Render the selected output format.
8. Decide exit code from findings and policy threshold.

## Examples
```text
mosec scan .
mosec scan . --format json --fail-on high
mosec scan ./repo --config mosec.toml --baseline baseline.json
```

## Reserved Future Commands
- `mosec baseline`
- `mosec triage`
- `mosec rules`
- `mosec report`

These names are reserved so the first release does not block later workflow commands.

## P0 Implementation Requirements
- `scan` and `version` must exist.
- `scan` must accept a positional path.
- `scan` must support `text` and `json`.
- `scan` must accept the filter and policy flags listed above.
- `scan` must support baseline and suppression file inputs.
- The parser contract must already allow SARIF, even if the renderer is added later.

## Non-Goals For The CLI Contract
- No daemon mode.
- No server mode.
- No interactive TUI.
- No embedded database contract yet.
- No IDE protocol contract yet.
