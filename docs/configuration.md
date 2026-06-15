# Configuration

MoSec uses TOML configuration files.

## Precedence

1. Command-line flags
2. Config file values
3. Built-in defaults

## Supported keys

- `root`
- `format`
- `include`
- `exclude`
- `baseline`
- `suppressions`
- `overrides`
- `parsers`
- `branch_fail_on`
- `fail_on`
- `max_noise`
- `fail_fast`
- `verbose`
- `quiet`

## Example

```toml
root = "."
format = "text"
include = ["src/**"]
exclude = ["**/__pycache__/**", "dist/**"]
baseline = "fixtures/baseline/baseline.json"
suppressions = "fixtures/suppressions/suppressions.json"
overrides = "fixtures/overrides/manual-overrides.json"
fail_on = "high"
max_noise = true

[parsers]
python = "python"
javascript = "text"
typescript = "text"

[branch_fail_on]
main = "high"
release = "critical"
```

## Notes

- Relative paths are resolved relative to the config file.
- `branch_fail_on` can raise or lower the policy threshold for named branches.
- `parsers` lets you override parser selection per language.

