from __future__ import annotations

import json
from typing import Any

from .policy import resolve_policy_threshold
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


def policy_branch_view_lines(state: SessionState) -> tuple[str, ...]:
    effective_threshold = resolve_policy_threshold(
        state.policy_threshold,
        state.policy_branch,
        state.branch_fail_on,
        state.policy_fail_on_explicit,
    )
    branch = state.policy_branch or "none"
    branch_threshold = state.branch_fail_on.get(state.policy_branch, "none") if state.policy_branch else "none"
    lines = [
        "Branch-specific policy review",
        f"Current branch: {branch}",
        f"Branch threshold: {branch_threshold}",
        f"Current threshold: {state.policy_threshold or 'none'}",
        f"Effective threshold: {effective_threshold or 'none'}",
        f"Explicit threshold: {'yes' if state.policy_fail_on_explicit else 'no'}",
    ]
    if state.policy_branch and state.policy_branch in state.branch_fail_on:
        lines.append(f"Branch override active for {state.policy_branch}.")
    else:
        lines.append("Branch override active: no")
    lines.append("")
    lines.append("Branch overrides")
    if state.branch_fail_on:
        for branch_name in sorted(state.branch_fail_on):
            marker = ">" if branch_name == state.policy_branch else " "
            lines.append(f"  {marker} {branch_name}: {state.branch_fail_on[branch_name]}")
    else:
        lines.append("  none")
    lines.append("")
    lines.append("Actions")
    lines.append("  /policy-branch | /policy-threshold | /policy | /back")
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


def policy_branch_view_payload(state: SessionState) -> dict[str, Any]:
    return {
        "policy_branch_review": {
            "threshold": state.policy_threshold,
            "effective_threshold": state.policy_effective_threshold(),
            "branch": state.policy_branch,
            "branch_threshold": state.branch_fail_on.get(state.policy_branch) if state.policy_branch else None,
            "branch_overrides": dict(state.branch_fail_on),
            "explicit_threshold": state.policy_fail_on_explicit,
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


def policy_branch_view_sarif(state: SessionState) -> dict[str, Any]:
    effective_threshold = state.policy_effective_threshold()
    branch_threshold = state.branch_fail_on.get(state.policy_branch) if state.policy_branch else None
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
                            "view_id": "policy-branch",
                            "view_title": "Branch-specific policy review",
                            "policy_threshold": state.policy_threshold,
                            "policy_effective_threshold": effective_threshold,
                            "policy_branch": state.policy_branch,
                            "policy_branch_threshold": branch_threshold,
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


def render_policy_branch_view_lines(state: SessionState) -> str:
    return "\n".join(policy_branch_view_lines(state))


def render_policy_branch_view_json(state: SessionState) -> str:
    return json.dumps(policy_branch_view_payload(state), indent=2, sort_keys=True)


def render_policy_branch_view_sarif(state: SessionState) -> str:
    return json.dumps(policy_branch_view_sarif(state), indent=2, sort_keys=True)
