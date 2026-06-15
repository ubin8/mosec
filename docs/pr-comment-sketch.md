# MoSec PR Comment Sketch

## Purpose
Define the first PR/MR comment format for MoSec findings.

This sketch focuses on how scan results are turned into review comments:
- file/line mapping
- short summary text
- remediation text
- severity text
- repeated-comment suppression
- baseline suppression

## Finding To Line Mapping
- A comment must map to one canonical file path and one start line.
- The mapping is taken from the normalized finding location.
- If a finding has no line number, it should not be posted as an inline comment.
- The bot should prefer `relative_path` plus `start_line` when creating review anchors.
- If the code host cannot anchor the line precisely, the comment should fall back to a summary comment.

## Comment Style
### Short Summary
- Use one short sentence that says what the finding is.
- Include the rule id in the header or first line.
- Keep the summary deterministic so repeated scans do not produce different text.

### Remediation
- Include one practical fix hint.
- Keep remediation short enough to fit in a code review comment.
- Prefer the remediation text already attached to the finding.

### Severity
- Severity should be visible at the start of the comment body or in a badge-like prefix.
- Critical and high findings should be visually harder to miss than medium or low findings.
- The comment text should not bury the severity below the fold.

## Repeated Comment Suppression
- The bot should reuse an existing comment when the same finding reappears.
- The dedupe key should be stable and based on the finding identity, path, and line.
- If the text changes but the finding identity does not, the bot should update the existing comment.
- The bot should not create multiple comments for the same finding in the same review.

## Baseline Suppression
- Findings matched by the baseline must not create new PR comments.
- Baseline hits should remain visible in the scan result, but not be posted as review noise.
- New findings should still generate comments even when old baseline findings are present.

## Comment Body Example
```text
MoSec [WEB-SQLI-001] high
Potential SQL injection in app.py:23
Remediation: Use parameterized queries or ORM bind parameters.
```

## Known Gaps
- Inline suggestion formatting is not defined yet.
- Thread resolution behavior depends on the code host.
- Multi-line diff anchoring is not defined yet.
