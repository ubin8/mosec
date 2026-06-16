from __future__ import annotations

import json

from .models import ScanResult
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
    selected = state.current_view_selected_finding()
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
            "count": len(state.current_view_findings()),
            "selected_finding": None if selected is None else selected.to_dict(),
            "findings": [finding.to_dict() for finding in state.current_view_findings()],
        },
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def render_current_view_sarif(state: SessionState) -> str:
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
