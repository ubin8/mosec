# MoSec Manual Override Sketch

## Purpose
Define how a reviewer can manually override the scanner's default suppression and baseline decisions.

## Scope
This sketch covers:
- manual override decisions on individual findings
- the supported override actions
- auditability of the override outcome

This sketch does not define:
- reviewer authentication
- multi-person approvals
- review queues

## Override Actions
MoSec manual overrides support two actions:
- `active`: keep the finding visible even if another rule would hide it
- `suppressed`: hide the finding even if no baseline or suppression would do so

## Model Rules
- Manual overrides must be explicit.
- Only one override action should apply per matched finding in the current MVP.
- Manual overrides take precedence over baseline and suppression rules.
- Manual overrides may be time-bounded with `expires_at`.
- Manual overrides must produce audit entries.

## Override Metadata
Override entries may carry:
- `author`
- `created_at`
- `expires_at`
- `scope`

## Intended Workflow
1. A reviewer creates an override rule for a specific finding location.
2. The override is loaded alongside baseline and suppression rules.
3. The override either keeps the finding active or suppresses it.
4. The decision is stored in the audit log and in finding metadata.

## Known Gaps
- No bulk overrides yet.
- No review queue or approval system yet.
- No UI for override creation yet.
