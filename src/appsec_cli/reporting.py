from __future__ import annotations

import json

from .models import ScanResult


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
                        "name": "mosec-cli",
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


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
