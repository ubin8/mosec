# Troubleshooting

## `config file does not exist`

The `--config` path must point to an existing TOML file.

## `verbose and quiet cannot both be enabled`

Choose one output style. The CLI rejects both flags at the same time.

## Exit code `1`

The scan found issues above the configured policy threshold.

## Exit code `3`

The scanner hit an unexpected runtime failure.

## No findings were reported

Possible reasons:

- the input is clean
- the file was excluded
- the parser did not recognize the file type
- the active rules do not cover that pattern yet

## SARIF import problems

Make sure the consumer understands SARIF 2.1.0 and that the file is not truncated during upload.

