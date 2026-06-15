# Fixture Corpus

## Purpose
Provide tiny, deterministic repositories and files that represent the first detection categories.

## Layout
```text
fixtures/
  config/
  reports/
  secrets/
  web/
  sca/
  mobile/
  baseline/
  suppressions/
  rules/
```

## Rules For Fixtures
- No real secrets.
- Keep examples minimal.
- One primary issue per file where possible.
- Include at least one safe example per category where helpful.
- Use stable paths and file names.

## Seed Corpora
- `secrets`: obvious hardcoded secret patterns
- `web`: SQLi and XSS style examples
- `sca`: dependency manifests and lockfiles
- `config`: CLI and scan config examples
- `mobile`: Android and iOS metadata examples
- `baseline`: baseline examples
- `suppressions`: suppression examples
- `reports`: golden JSON or SARIF examples
- `rules`: built-in rule pack examples
