# MoSec Suppression Review Sketch

## Purpose
Define how suppression entries move through review before they are allowed to hide findings.

## Scope
This sketch covers:
- suppression review states
- the fields needed to record who reviewed a suppression
- the rule that only approved suppressions may suppress findings

This sketch does not define:
- reviewer authentication
- approval workflows across teams
- external review tools

## Review States
MoSec suppressions use a small review state model:
- `pending`: the suppression is waiting for review
- `approved`: the suppression may suppress findings
- `rejected`: the suppression must not suppress findings

## Model Rules
- Suppressions should default to `approved` for backward compatibility unless explicitly marked otherwise.
- Only `approved` suppressions may match findings.
- Review metadata should remain attached to the suppression entry.
- Expired suppressions must still be blocked even if approved.

## Review Metadata
The suppression review state may be accompanied by:
- `reviewed_by`
- `reviewed_at`
- `review_note`

## Intended Workflow
1. A suppression entry is created with a reason.
2. The suppression is reviewed and assigned a review state.
3. If approved, it may suppress matching findings.
4. If pending or rejected, it must not suppress matching findings.

## Known Gaps
- No external approval service yet.
- No dedicated review audit trail yet.
