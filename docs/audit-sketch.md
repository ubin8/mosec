# MoSec Audit Sketch

## Purpose
Define the first shared audit-log shape for decisions that MoSec makes while scanning and filtering findings.

## Scope
This sketch covers:
- recording decisions in a structured way
- keeping audit entries separate from findings
- preserving the decision context for later review

This sketch does not define:
- user authentication
- role-based access control
- retention policies
- external audit storage

## Audit Entry Model
An audit entry captures a decision event with enough context to reconstruct why it happened.

The first release uses these fields:
- `action`
- `subject_type`
- `subject_id`
- `decision`
- `reason`
- `actor`
- `created_at`
- `metadata`

## Decision Types
MoSec should record at least:
- baseline decisions
- suppression decisions
- policy decisions

Later workflow layers may record:
- triage decisions
- review approvals
- manual overrides

## Model Rules
- Audit entries must be append-only at the scan-result level.
- Audit entries must be serializable in JSON and visible in SARIF properties.
- Audit entries must not replace the underlying finding status.
- Audit entries should carry a stable subject identifier and free-form metadata.

## Intended Workflow
1. The scanner evaluates a finding or scan policy.
2. The workflow emits an audit entry for the decision.
3. The report stores the audit entries with the scan result.
4. Later review systems can use the audit log for traceability.

## Known Gaps
- No external persistence backend yet.
- No retention policy yet.
- No immutable event store yet.
