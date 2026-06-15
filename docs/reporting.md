# Reporting and CI Usage

## Report formats

MoSec currently emits:

- text
- JSON
- SARIF

## Text output

Good for interactive use and quick inspection.

## JSON output

Good for integrations that want the full machine-readable model.

## SARIF output

Good for:

- code hosts
- CI pipelines
- artifact storage
- security dashboards that understand SARIF

## Policy gating

MoSec can fail the scan when findings meet or exceed the configured threshold.

- `--fail-on high`
- `--fail-on critical`

Exit code `1` means the scan was valid but the policy threshold was exceeded.

## CI usage pattern

Use `mosec scan` in CI and archive the JSON or SARIF output as an artifact.

Example:

```bash
mosec scan . --format sarif --fail-on high
```

Native GitHub and GitLab integrations are planned as product work; SARIF export is the current portable integration surface.

