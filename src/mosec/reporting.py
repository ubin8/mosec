from __future__ import annotations

import json

from .models import ScanResult
from .rule_browser import (
    render_rule_browser_json,
    render_rule_browser_lines,
    render_rule_browser_sarif,
    render_rule_detail_json,
    render_rule_detail_lines,
    render_rule_detail_sarif,
)
from .policy_views import render_policy_view_json, render_policy_view_lines, render_policy_view_sarif
from .policy_views import render_policy_branch_view_json, render_policy_branch_view_lines, render_policy_branch_view_sarif
from .audit_views import render_audit_trail_view_json, render_audit_trail_view_lines, render_audit_trail_view_sarif
from .manual_override_views import render_manual_override_view_json, render_manual_override_view_lines, render_manual_override_view_sarif
from .state import SessionState


def render_text(result: ScanResult) -> str:
    return result.to_text()


def render_json(result: ScanResult) -> str:
    return result.to_json()


def render_sarif(result: ScanResult) -> str:
    rules_by_id: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []

    for finding in result.findings:
        rules_by_id.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.message},
                "fullDescription": {"text": finding.message},
                "help": {"text": finding.remediation or finding.message},
                "properties": {
                    "severity": finding.severity.value,
                    "confidence": finding.confidence.value,
                    "category": finding.category,
                    "owasp": list(finding.owasp),
                    "cwe": list(finding.cwe),
                },
            },
        )
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.severity.value),
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(finding.location.path)},
                            "region": {
                                "startLine": finding.location.start_line,
                                "startColumn": finding.location.start_column,
                            },
                        }
                    }
                ],
                "properties": {
                    "id": finding.id,
                    "confidence": finding.confidence.value,
                    "status": finding.status.value,
                    "triage_status": finding.triage_status.value,
                    "triage_reason": finding.triage_reason,
                    "triage_note": finding.triage_note,
                    "category": finding.category,
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mosec",
                        "version": "0.1.0",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "root": str(result.root),
                            "started_at": result.started_at,
                            "finished_at": result.finished_at,
                            "tool_version": result.tool_version,
                            "policy_branch": result.policy_branch,
                            "files_seen": result.stats.files_seen,
                            "files_selected": result.stats.files_selected,
                            "findings": result.stats.findings,
                            "baselined_findings": result.stats.baselined_findings,
                            "suppressed_findings": result.stats.suppressed_findings,
                            "policy_threshold": result.policy_threshold,
                            "policy_effective_threshold": result.policy_effective_threshold,
                            "policy_decision": result.policy_decision,
                            "audit_log": [entry.to_dict() for entry in result.audit_log],
                            "rule_packs": [pack.to_dict() for pack in result.rule_packs],
                        },
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=True)


def render_current_view_text(state: SessionState) -> str:
    if state.current_view == "rule-detail":
        lines = [
            f"view: {state.current_view}",
            f"title: {state.current_view_title()}",
            f"workspace: {state.workspace}",
            f"mode: {state.scan_mode}",
            f"format: {state.output_format}",
        ]
        selected = state.current_view_selected_rule()
        if selected is not None:
            lines.append(f"selected: {selected.id} - {selected.name}")
        lines.extend(state.summary_lines())
        lines.extend(
            render_rule_detail_lines(
                state.rule_packs,
                selected_pack_index=state.selected_rule_pack_index,
                selected_rule_index=state.selected_rule_index,
            )
        )
        return "\n".join(lines)

    if state.current_view == "policy":
        lines = [
            f"view: {state.current_view}",
            f"title: {state.current_view_title()}",
            f"workspace: {state.workspace}",
            f"mode: {state.scan_mode}",
            f"format: {state.output_format}",
        ]
        lines.extend(state.summary_lines())
        lines.extend(render_policy_view_lines(state).splitlines())
        return "\n".join(lines)

    if state.current_view == "policy-branch":
        lines = [
            f"view: {state.current_view}",
            f"title: {state.current_view_title()}",
            f"workspace: {state.workspace}",
            f"mode: {state.scan_mode}",
            f"format: {state.output_format}",
        ]
        lines.extend(state.summary_lines())
        lines.extend(render_policy_branch_view_lines(state).splitlines())
        return "\n".join(lines)

    if state.current_view == "audit-trail":
        lines = [
            f"view: {state.current_view}",
            f"title: {state.current_view_title()}",
            f"workspace: {state.workspace}",
            f"mode: {state.scan_mode}",
            f"format: {state.output_format}",
        ]
        lines.extend(state.summary_lines())
        lines.extend(render_audit_trail_view_lines(state).splitlines())
        return "\n".join(lines)

    if state.current_view == "manual-overrides":
        lines = [
            f"view: {state.current_view}",
            f"title: {state.current_view_title()}",
            f"workspace: {state.workspace}",
            f"mode: {state.scan_mode}",
            f"format: {state.output_format}",
        ]
        lines.extend(state.summary_lines())
        lines.extend(render_manual_override_view_lines(state).splitlines())
        return "\n".join(lines)

    if state.current_view == "rules":
        lines = [
            f"view: {state.current_view}",
            f"title: {state.current_view_title()}",
            f"workspace: {state.workspace}",
            f"mode: {state.scan_mode}",
            f"format: {state.output_format}",
        ]
        selected = state.current_view_selected_rule()
        if selected is not None:
            lines.append(f"selected: {selected.id} - {selected.name}")
        lines.extend(state.summary_lines())
        lines.extend(
            render_rule_browser_lines(
                state.rule_packs,
                selected_pack_index=state.selected_rule_pack_index,
                selected_rule_index=state.selected_rule_index,
            )
        )
        return "\n".join(lines)

    lines = [
        f"view: {state.current_view}",
        f"title: {state.current_view_title()}",
        f"workspace: {state.workspace}",
        f"mode: {state.scan_mode}",
        f"format: {state.output_format}",
        f"findings: {len(state.current_view_findings())}",
    ]
    selected = state.current_view_selected_finding()
    if selected is not None:
        lines.append(f"selected: {selected.to_summary()}")
    if state.findings_search_query is not None or state.findings_severity_filters:
        lines.append(
            "filters: "
            f"search={state.findings_search_query or 'none'}, "
            f"severity={', '.join(state.findings_severity_filters) if state.findings_severity_filters else 'all'}"
        )
    lines.extend(state.summary_lines())
    findings = state.current_view_findings()
    if findings:
        lines.append("findings:")
        lines.extend(f"- {finding.to_summary()}" for finding in findings)
    else:
        lines.append("findings:")
        lines.append("- none")
    return "\n".join(lines)


def render_current_view_json(state: SessionState) -> str:
    selected_finding = state.current_view_selected_finding()
    selected_rule = state.current_view_selected_rule()
    current_view_findings = state.current_view_findings()
    current_view_rules = state.current_view_rules()
    current_view_audit_entries = state.current_view_audit_entries()
    current_view_manual_override_entries = state.current_view_manual_override_entries()
    current_view_manual_override_findings = state.current_view_manual_override_findings()
    current_view_count = len(current_view_findings) if current_view_findings else len(current_view_rules)
    if current_view_count == 0 and current_view_audit_entries:
        current_view_count = len(current_view_audit_entries)
    if current_view_count == 0 and current_view_manual_override_entries:
        current_view_count = len(current_view_manual_override_entries)
    payload = {
        "view": {
            "id": state.current_view,
            "title": state.current_view_title(),
        },
        "session": {
            "workspace": state.workspace,
            "scan_mode": state.scan_mode,
            "output_format": state.output_format,
            "status_text": state.status_text,
            "status_kind": state.status_kind,
            "last_scan_target": state.last_scan_target,
            "last_scan_mode": state.last_scan_mode,
            "last_scan_format": state.last_scan_format,
            "last_command": state.last_command,
        },
        "filters": {
            "search_query": state.findings_search_query,
            "severity": list(state.findings_severity_filters),
        },
        "current_view": {
            "count": current_view_count,
            "selected_finding": None if selected_finding is None else selected_finding.to_dict(),
            "findings": [finding.to_dict() for finding in current_view_findings],
            "rules": [rule.to_dict() for rule in current_view_rules],
            "selected_rule": None if selected_rule is None else selected_rule.to_dict(),
            "audit_entries": [entry.to_dict() for entry in current_view_audit_entries],
            "manual_override_entries": [entry.to_dict() for entry in current_view_manual_override_entries],
            "manual_override_findings": [finding.to_dict() for finding in current_view_manual_override_findings],
        },
    }
    if state.current_view == "rule-detail":
        payload["rule_detail"] = json.loads(
            render_rule_detail_json(
                state.rule_packs,
                selected_pack_index=state.selected_rule_pack_index,
                selected_rule_index=state.selected_rule_index,
            )
        )
    elif state.current_view == "rules":
        payload["rule_browser"] = json.loads(
            render_rule_browser_json(
                state.rule_packs,
                selected_pack_index=state.selected_rule_pack_index,
                selected_rule_index=state.selected_rule_index,
            )
        )
    elif state.current_view == "policy":
        payload["policy_editor"] = json.loads(render_policy_view_json(state))
    elif state.current_view == "policy-branch":
        payload["policy_branch_review"] = json.loads(render_policy_branch_view_json(state))
    elif state.current_view == "audit-trail":
        payload["audit_trail"] = json.loads(render_audit_trail_view_json(state))["audit_trail"]
    elif state.current_view == "manual-overrides":
        payload["manual_overrides"] = json.loads(render_manual_override_view_json(state))["manual_overrides"]
    return json.dumps(payload, indent=2, sort_keys=True)


def render_current_view_sarif(state: SessionState) -> str:
    if state.current_view == "rule-detail":
        return render_rule_detail_sarif(
            state.rule_packs,
            selected_pack_index=state.selected_rule_pack_index,
            selected_rule_index=state.selected_rule_index,
        )
    if state.current_view == "rules":
        return render_rule_browser_sarif(
            state.rule_packs,
            selected_pack_index=state.selected_rule_pack_index,
            selected_rule_index=state.selected_rule_index,
        )
    if state.current_view == "policy":
        return render_policy_view_sarif(state)
    if state.current_view == "policy-branch":
        return render_policy_branch_view_sarif(state)
    if state.current_view == "audit-trail":
        return render_audit_trail_view_sarif(state)
    if state.current_view == "manual-overrides":
        return render_manual_override_view_sarif(state)

    findings = state.current_view_findings()
    selected = state.current_view_selected_finding()
    rules_by_id: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []

    for finding in findings:
        rules_by_id.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.message},
                "fullDescription": {"text": finding.message},
                "help": {"text": finding.remediation or finding.message},
                "properties": {
                    "severity": finding.severity.value,
                    "confidence": finding.confidence.value,
                    "category": finding.category,
                    "owasp": list(finding.owasp),
                    "cwe": list(finding.cwe),
                },
            },
        )
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.severity.value),
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(finding.location.path)},
                            "region": {
                                "startLine": finding.location.start_line,
                                "startColumn": finding.location.start_column,
                            },
                        }
                    }
                ],
                "properties": {
                    "id": finding.id,
                    "confidence": finding.confidence.value,
                    "status": finding.status.value,
                    "triage_status": finding.triage_status.value,
                    "triage_reason": finding.triage_reason,
                    "triage_note": finding.triage_note,
                    "category": finding.category,
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mosec",
                        "version": "0.1.0",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "view_id": state.current_view,
                            "view_title": state.current_view_title(),
                            "workspace": state.workspace,
                            "scan_mode": state.scan_mode,
                            "output_format": state.output_format,
                            "status_text": state.status_text,
                            "status_kind": state.status_kind,
                            "search_query": state.findings_search_query,
                            "severity_filters": list(state.findings_severity_filters),
                            "findings": len(findings),
                            "selected_finding": None if selected is None else selected.to_dict(),
                        },
                    }
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=True)


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
