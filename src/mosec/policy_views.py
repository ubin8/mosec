from __future__ import annotations

import json
from typing import Any

from .state import SessionState


def _policy_threshold_lines(state: SessionState) -> list[str]:
    lines: list[str] = []
    if state.branch_fail_on:
        lines.append("Branch thresholds:")
        for branch in sorted(state.branch_fail_on):
            lines.append(f"  - {branch}: {state.branch_fail_on[branch]}")
    else:
        lines.append("Branch thresholds: none")
    return lines


def policy_view_lines(state: SessionState) -> tuple[str, ...]:
    effective_threshold = state.policy_effective_threshold()
    lines = [
        "Policy editor",
        f"Current threshold: {state.policy_threshold or 'none'}",
        f"Effective threshold: {effective_threshold or 'none'}",
        f"Current branch: {state.policy_branch or 'none'}",
        f"Explicit threshold: {'yes' if state.policy_fail_on_explicit else 'no'}",
        f"Branch overrides: {len(state.branch_fail_on)}",
        f"Supported thresholds: low | medium | high | critical | none",
    ]
    lines.extend(_policy_threshold_lines(state))
    lines.append("")
    lines.append("Actions")
    lines.append("  /policy-threshold | /policy | /back")
    return tuple(lines)


def policy_view_payload(state: SessionState) -> dict[str, Any]:
    return {
        "policy": {
            "threshold": state.policy_threshold,
            "effective_threshold": state.policy_effective_threshold(),
            "branch": state.policy_branch,
            "explicit_threshold": state.policy_fail_on_explicit,
            "branch_fail_on": dict(state.branch_fail_on),
            "supported_thresholds": ["low", "medium", "high", "critical", "none"],
        }
    }


def policy_view_sarif(state: SessionState) -> dict[str, Any]:
    effective_threshold = state.policy_effective_threshold()
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
                            "view_id": "policy",
                            "view_title": "Policy",
                            "policy_threshold": state.policy_threshold,
                            "policy_effective_threshold": effective_threshold,
                            "policy_branch": state.policy_branch,
                            "policy_explicit_threshold": state.policy_fail_on_explicit,
                            "branch_fail_on": dict(state.branch_fail_on),
                        },
                    }
                ],
            }
        ],
    }


def render_policy_view_lines(state: SessionState) -> str:
    return "\n".join(policy_view_lines(state))


def render_policy_view_json(state: SessionState) -> str:
    return json.dumps(policy_view_payload(state), indent=2, sort_keys=True)


def render_policy_view_sarif(state: SessionState) -> str:
    return json.dumps(policy_view_sarif(state), indent=2, sort_keys=True)
