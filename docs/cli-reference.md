# CLI Reference

## Commands

### `mosec scan <path>`

Scan a repository or a single file.

Useful options:

- `--format text|json|sarif`
- `--config <path>`
- `--branch <name>`
- `--include <pattern>` repeated
- `--exclude <pattern>` repeated
- `--baseline <path>`
- `--suppressions <path>`
- `--overrides <path>`
- `--fail-on low|medium|high|critical`
- `--max-noise`
- `--fail-fast`
- `--verbose`
- `--quiet`

### `mosec version`

Print the installed CLI version.

## Exit codes

- `0`: scan completed successfully
- `1`: policy threshold was exceeded
- `2`: invalid command-line usage
- `3`: unexpected runtime failure

## Example invocations

```bash
mosec scan .
mosec scan . --format json --fail-on high
mosec scan ./repo --config fixtures/config/appsec.toml --baseline fixtures/baseline/baseline.json
```

