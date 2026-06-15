# Test Strategy

## Purpose
Keep the scanner honest by using small fixtures, golden outputs, and contract tests instead of only unit tests.

## Test Layers
### Unit Tests
- data model serialization
- rule metadata validation
- config parsing
- CLI argument parsing
- exit code mapping

### Integration Tests
- repository scanning
- file selection and exclusion
- baseline comparison
- suppression handling
- JSON and SARIF rendering

### Fixture Tests
- secrets corpus
- SQL injection corpus
- XSS corpus
- dependency corpus
- baseline corpus
- suppression corpus

### Golden Tests
- stable JSON snapshots
- stable SARIF snapshots
- stable text summaries

## Test Matrix
| Area | Unit | Integration | Golden | Fixture |
| --- | --- | --- | --- | --- |
| CLI contract | x | x | x |  |
| config loading | x | x |  |  |
| rule loading | x | x |  | x |
| findings schema | x |  | x |  |
| secrets scanning | x | x | x | x |
| dependency scanning | x | x | x | x |
| baseline and suppressions | x | x | x | x |
| JSON and SARIF export | x | x | x |  |

## Fixture Principles
- Minimal files only.
- No real secrets.
- One issue per file if possible.
- Positive and negative examples should be paired.
- Fixtures must be deterministic.
- File names should clearly describe the scenario under test.
- Every fixture category should include at least one safe control file.

## Required Coverage For P0
- `scan` command works on a folder.
- `scan` command works on a single file.
- finding and rule objects serialize correctly.
- baseline filtering changes output as expected.
- suppressions remove only the intended findings.
- report output is stable across repeated runs.

## Regression Gates
- Do not merge if JSON schema changes are unreviewed.
- Do not merge if SARIF structure breaks consumers.
- Do not merge if rule ids or severities are changed without intent.
- Do not merge if new rules create noisy duplicates in fixtures.
- Do not merge if fixture outputs change without an explicit update to the golden files.
- Do not merge if baseline or suppression behavior becomes nondeterministic.

## Acceptance Checks
- smoke test passes
- fixture scans pass
- rule model serialization passes
- finding model serialization passes
- CLI output is parseable
- SARIF export validates against the selected schema level
