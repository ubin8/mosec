# MoSec Collaboration Sketch

## Purpose
Define the first collaboration workflow for MoSec after the CI runners have produced scan artifacts.

This sketch covers:
- token-based authentication
- artifact upload behavior
- comment-bot behavior
- deduplicated PR comments

The more detailed policy gates, PR formatting rules, and false-positive workflows remain in the backlog.

## Token-Based Authentication
- GitHub uses the repository-scoped `GITHUB_TOKEN` or a narrowly scoped PAT when cross-repo access is required.
- GitLab uses `CI_JOB_TOKEN` for same-project operations or a protected project token when elevated permissions are required.
- Tokens must be read/write only where necessary and should not be used outside CI job scope.
- Authentication is limited to:
  - posting or updating PR/MR comments
  - uploading scan artifacts
  - reading the repository checkout
- No long-lived credentials are stored in the repository.

## Artifact Upload
- MoSec should export machine-readable scan results as CI artifacts.
- The primary artifact formats are:
  - `sarif`
  - `json`
- Artifact names should include the tool name and format, for example:
  - `mosec-scan.sarif`
  - `mosec-scan.json`
- Artifacts should be uploaded even when the scan returns findings.
- Artifact retention should be configurable by the CI provider, not by MoSec itself.
- Artifact uploads should not block the scan result from being surfaced.

## Comment Bot Behavior
- Comments are posted only for pull requests and merge requests, not for branch pushes.
- The bot should summarize only actionable findings.
- Each comment should include:
  - rule id
  - severity
  - file path
  - line number
  - short remediation hint
- Baseline findings should not generate new comments.
- Existing comments should be updated when the underlying finding changes.
- The bot should stay silent when there are no new actionable findings.

## Deduplicated PR Comments
- Dedupe keys should be stable across repeated runs.
- A dedupe key should be derived from:
  - `rule_id`
  - `relative_path`
  - `start_line`
  - finding fingerprint when available
- If a matching comment already exists, the bot should update it instead of posting a new one.
- If the finding disappears, the corresponding comment can be resolved or left for manual cleanup depending on provider support.
- Deduplication applies to the bot layer, not to the underlying scan result.

## Known Gaps
- Branch-specific policy overrides are not defined here.
- Approval workflows for suppressions are not defined here.
- Inline review summaries are not defined here.
