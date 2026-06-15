# MoSec MVP Spec

## Purpose
Define the first shippable version of the MoSec CLI before implementation starts.

This MVP is intentionally narrow: it should prove that the scanner can analyze a local repository, produce useful findings, and export stable machine-readable output without depending on a running application.

## Product Decision
- Build a Python-first CLI scanner for MoSec.
- Focus on local repository analysis only.
- Keep the first release repository-centric, not platform-centric.
- Make the first release useful for developers and security reviewers, not for enterprise workflow orchestration.

## Target Users
- Individual developers who want fast repo checks.
- Security engineers doing triage on pull requests or branches.
- Platform teams that need a deterministic CLI artifact for CI.

## MVP Scope
### In Scope
- Local scan from a CLI command.
- Python implementation for orchestration and first detectors.
- Basic language and ecosystem detection.
- Secrets scanning.
- Dependency scanning for Python and Node ecosystems.
- Simple Web SAST patterns for Python and JavaScript/TypeScript.
- Text output for humans.
- JSON output for automation and tests.
- SARIF output for code hosts and security tooling.
- Baseline support.
- Suppression support with auditability.

### Out of Scope
- Full DAST.
- Full MAST.
- Deep cross-language taint tracking.
- Mobile-specific rules.
- Dashboard, accounts, or org management.
- AI-assisted remediation.
- Jira, Linear, or similar integrations.
- Rust dependency for the first release.

## Initial Supported Inputs
- Python source repositories.
- JavaScript and TypeScript source repositories.
- Python dependency manifests and lockfiles.
- Node dependency manifests and lockfiles.
- Plain configuration files needed for filtering and scan context.

## Initial Supported Findings
### Secrets
- API keys.
- Tokens.
- Private keys.
- Obvious hardcoded passwords.

### Dependency Issues
- Known vulnerable package versions.
- Direct and transitive dependency matches.

### Web SAST
- Obvious SQL injection patterns.
- Obvious XSS patterns.
- Obvious unsafe string interpolation into dangerous sinks.

## Explicit Non-Goals For MVP
- No attempt to be language-complete.
- No attempt to model every framework.
- No attempt to solve all false positives up front.
- No attempt to detect every OWASP or CWE category.
- No attempt to build a rich UI before the scan core is trusted.

## First Release Contract
### CLI
- `mosec scan <path>` is the main command.
- `mosec version` prints the installed version.
- The CLI must support at least `text` and `json` output.
- SARIF must be planned and schema-compatible from the start.

### Outputs
- JSON is the canonical machine output.
- SARIF is the interoperability export.
- Text is for direct developer consumption.

### Data Contracts
- Finding and rule models must be stable enough to serialize.
- Severity and confidence are separate concepts.
- Findings must carry location, evidence, and rule references.

## Success Criteria
The MVP is successful when all of the following are true:
- A developer can run one CLI command against a local repository.
- The scan finishes without executing the application.
- The scan produces at least one meaningful finding class for:
  - secrets
  - dependencies
  - basic web code issues
- JSON output is parseable and stable across repeated runs.
- SARIF output can be consumed by downstream tooling.
- Baseline and suppressions can hide known findings without masking new ones.
- The scanner remains deterministic on repeated runs over the same input.

## Quality Bar
- Failures should be isolated to a file or scan unit, not the whole run.
- Findings should be explainable, not just machine-produced flags.
- Default output should be low-noise and actionable.
- The CLI should be small enough to understand and extend.

## MVP Build Sequence
### Step 1 - Lock the implementation contract
- Finalize CLI commands and flags.
- Finalize the configuration format.
- Finalize finding and rule schema fields.
- Finalize output formats and exit codes.

### Step 2 - Build the scan shell
- Implement repository ingestion.
- Implement file selection and exclusion handling.
- Implement basic language and ecosystem detection.
- Capture scan statistics and partial failures.

### Step 3 - Add the first detectors
- Add secrets detection.
- Add dependency scanning.
- Add the first web pattern rules.
- Normalize findings into a shared schema.

### Step 4 - Add outputs and control flow
- Add text and JSON rendering.
- Add SARIF rendering.
- Add baseline comparison.
- Add suppression handling.
- Add policy-friendly exit behavior.

### Step 5 - Add fixtures and regression protection
- Add fixture repositories and files.
- Add smoke tests.
- Add golden output tests.
- Add rule-model and finding-model tests.

## Implementation Assumptions
- Python 3.11 is the baseline runtime.
- TOML is the preferred config and rule-pack format.
- Local filesystem scanning is the only input mode for the MVP.
- Rust can be introduced later without changing the CLI contract.

## Exit Criteria For This Document
- The MVP scope is narrow enough that implementation can start.
- The first release boundaries are clear.
- The CLI and data contracts are explicit.
- The MVP can be broken into engineering tickets without more product decisions.
