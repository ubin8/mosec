from __future__ import annotations

import json
from typing import Any

from .state import SessionState


def audit_trail_view_lines(state: SessionState) -> tuple[str, ...]:
    lines = [
        "Audit trail",
        f"Audit entries: {len(state.audit_log)}",
    ]
    if not state.audit_log:
        lines.extend(
            [
                "No audit entries available yet.",
                "Run commands, scans, or policy changes to populate this view.",
            ]
        )
        lines.append("")
        lines.append("Actions")
        lines.append("  /audit-trail | /audit | /back")
        return tuple(lines)

    lines.append("")
    lines.append("Entries")
    for entry in state.audit_log:
        summary = entry.to_summary()
        details: list[str] = []
        if entry.actor is not None:
            details.append(f"actor={entry.actor}")
        if entry.created_at is not None:
            details.append(f"at={entry.created_at}")
        if details:
            summary = f"{summary} | {', '.join(details)}"
        lines.append(f"  - {summary}")
    lines.append("")
    lines.append("Actions")
    lines.append("  /audit-trail | /audit | /back")
    return tuple(lines)


def audit_trail_view_payload(state: SessionState) -> dict[str, Any]:
    return {
        "audit_trail": {
            "count": len(state.audit_log),
            "entries": [entry.to_dict() for entry in state.audit_log],
        }
    }


def audit_trail_view_sarif(state: SessionState) -> dict[str, Any]:
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
                            "view_id": "audit-trail",
                            "view_title": "Audit trail",
                            "audit_entries": len(state.audit_log),
                            "audit_log": [entry.to_dict() for entry in state.audit_log],
                        },
                    }
                ],
            }
        ],
    }


def render_audit_trail_view_lines(state: SessionState) -> str:
    return "\n".join(audit_trail_view_lines(state))


def render_audit_trail_view_json(state: SessionState) -> str:
    return json.dumps(audit_trail_view_payload(state), indent=2, sort_keys=True)


def render_audit_trail_view_sarif(state: SessionState) -> str:
    return json.dumps(audit_trail_view_sarif(state), indent=2, sort_keys=True)
