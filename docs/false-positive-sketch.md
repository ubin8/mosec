# MoSec False-Positive Sketch

## Purpose
Define the first triage state model for findings so that later suppression, review, audit, and override workflows can build on a stable base.

## Scope
This sketch covers:
- triaging status on each finding
- the separation between triage state and lifecycle status
- the intended starting states for new findings
- structured triage justification fields

This sketch does not define:
- review approval flows
- manual overrides

## Triage Status Model
MoSec findings carry a dedicated triage status that is separate from the lifecycle status.

The first release uses:
- `untriaged`: the finding has not been reviewed yet
- `in_review`: the finding is being actively reviewed
- `triaged`: the finding has a recorded triage outcome

## Model Rules
- New findings should default to `untriaged`.
- Triage status must survive baseline and suppression cloning.
- Triage status must be serializable in JSON and visible in the shared data schema.
- Triage status must not replace lifecycle status such as `new`, `suppressed`, or `baselined`.
- Triage justifications should be stored in dedicated fields, not only in metadata blobs.
- `triage_reason` should capture the decision rationale.
- `triage_note` may capture reviewer context or follow-up details.
- Suppression entries may carry `expires_at` to make the decision time-bounded.
- Expired suppressions must not match findings.

## Intended Workflow
1. Scanner emits a new finding with `triage_status = untriaged`.
2. A reviewer moves the finding to `in_review` while inspecting it.
3. The reviewer records `triage_reason` and optionally `triage_note`.
4. The reviewer marks the finding `triaged` once the review is complete.
5. Later workflow layers may attach suppression decisions and additional review metadata.

Suppression review states and metadata are defined in [suppression-review-sketch.md](/home/lucas/MO/docs/suppression-review-sketch.md).
Manual override behavior is defined in [manual-override-sketch.md](/home/lucas/MO/docs/manual-override-sketch.md).

## Known Gaps
- No manual override policy yet.
