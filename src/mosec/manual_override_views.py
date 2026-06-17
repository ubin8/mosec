from __future__ import annotations

import json
from typing import Any

from .state import SessionState


def _manual_override_summary(entry: Any) -> str:
    subject = entry.subject_id or "unknown"
    parts = [
        entry.decision or "unknown",
        entry.subject_type,
        subject,
    ]
    if entry.reason:
        parts.append(f"reason={entry.reason}")
    if entry.actor:
        parts.append(f"actor={entry.actor}")
    return " ".join(parts)


def manual_override_view_lines(state: SessionState) -> tuple[str, ...]:
    entries = state.current_view_manual_override_entries()
    findings = state.current_view_manual_override_findings()
    active = [entry for entry in entries if entry.decision == "active"]
    suppressed = [entry for entry in entries if entry.decision == "suppressed"]
    lines = [
        "Manual override management",
        f"Manual overrides: {len(entries)}",
        f"Active overrides: {len(active)}",
        f"Suppressed overrides: {len(suppressed)}",
        f"Affected findings: {len(findings)}",
    ]
    if not entries:
        lines.extend(
            [
                "No manual override entries recorded yet.",
                "Run a scan with an overrides file to populate this view.",
            ]
        )
    else:
        lines.append("")
        lines.append("Override entries")
        for entry in entries:
            lines.append(f"  - {_manual_override_summary(entry)}")
        if findings:
            lines.append("")
            lines.append("Affected findings")
            for finding in findings:
                decision = finding.metadata.get("manual_override_decision", "unknown")
                reason = finding.metadata.get("manual_override_reason", "n/a")
                lines.append(
                    f"  - {finding.severity.value.title()} {finding.rule_id} "
                    f"{finding.location.path}:{finding.location.start_line} "
                    f"| decision={decision} | reason={reason}"
                )
    lines.append("")
    lines.append("Actions")
    lines.append("  /manual-overrides | /overrides | /audit-trail | /back")
    return tuple(lines)


def manual_override_view_payload(state: SessionState) -> dict[str, Any]:
    entries = state.current_view_manual_override_entries()
    findings = state.current_view_manual_override_findings()
    return {
        "manual_overrides": {
            "count": len(entries),
            "active": len([entry for entry in entries if entry.decision == "active"]),
            "suppressed": len([entry for entry in entries if entry.decision == "suppressed"]),
            "entries": [entry.to_dict() for entry in entries],
            "findings": [finding.to_dict() for finding in findings],
        }
    }


def manual_override_view_sarif(state: SessionState) -> dict[str, Any]:
    entries = state.current_view_manual_override_entries()
    findings = state.current_view_manual_override_findings()
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mosec",
                        "version": "0.1.0",
                        "rules": [],
                    }
                },
                "results": [],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "view_id": "manual-overrides",
                            "view_title": "Manual override management",
                            "manual_override_count": len(entries),
                            "manual_override_active": len([entry for entry in entries if entry.decision == "active"]),
                            "manual_override_suppressed": len([entry for entry in entries if entry.decision == "suppressed"]),
                            "manual_override_entries": [entry.to_dict() for entry in entries],
                            "manual_override_findings": [finding.to_dict() for finding in findings],
                        },
                    }
                ],
            }
        ],
    }


def render_manual_override_view_lines(state: SessionState) -> str:
    return "\n".join(manual_override_view_lines(state))


def render_manual_override_view_json(state: SessionState) -> str:
    return json.dumps(manual_override_view_payload(state), indent=2, sort_keys=True)


def render_manual_override_view_sarif(state: SessionState) -> str:
    return json.dumps(manual_override_view_sarif(state), indent=2, sort_keys=True)
