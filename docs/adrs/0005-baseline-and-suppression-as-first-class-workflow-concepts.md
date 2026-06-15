# ADR 0005: Baseline And Suppression As First-Class Workflow Concepts

## Status
accepted

## Context
The scanner must support repeated runs against the same repository without re-reporting the same accepted issues.

## Decision
- Baseline entries are separate from suppressions.
- Suppressions must include a human reason.
- Baseline matching is fingerprint-based and rule-aware.
- Suppression and baseline state must be visible in the data model.

## Consequences
- Repeated scans can stay low-noise.
- Security reviewers can distinguish accepted legacy issues from consciously suppressed findings.
- The workflow becomes auditable.

