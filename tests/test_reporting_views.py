from __future__ import annotations

import json
from pathlib import Path

from mosec.findings import CodeLocation, Confidence, Evidence, Finding, FindingStatus, Severity
from mosec.reporting import render_current_view_json, render_current_view_sarif, render_current_view_text
from mosec.state import SessionState


def _finding(tmp_path: Path, finding_id: str, rule_id: str, line: int, severity: Severity, status: FindingStatus) -> Finding:
    return Finding(
        id=finding_id,
        rule_id=rule_id,
        title=finding_id,
        message=finding_id,
        severity=severity,
        confidence=Confidence.MEDIUM,
        location=CodeLocation(path=tmp_path / "app.py", start_line=line),
        category="example",
        evidence=Evidence(snippet=finding_id),
        status=status,
    )


def test_render_current_view_json_exports_findings_view(tmp_path: Path) -> None:
    state = SessionState()
    state.store_scan_results(
        [
            _finding(tmp_path, "active-1", "RULE-ACTIVE", 1, Severity.HIGH, FindingStatus.NEW),
        ],
        suppressed_findings=[
            _finding(tmp_path, "suppressed-1", "RULE-SUPPRESSED", 2, Severity.LOW, FindingStatus.SUPPRESSED),
        ],
    )
    state.set_findings_search_query("active")
    state.set_current_view("findings")

    payload = json.loads(render_current_view_json(state))

    assert payload["view"]["id"] == "findings"
    assert payload["view"]["title"] == "Findings"
    assert payload["current_view"]["count"] == 1
    assert payload["current_view"]["findings"][0]["id"] == "active-1"
    assert payload["filters"]["search_query"] == "active"


def test_render_current_view_sarif_exports_baselined_view(tmp_path: Path) -> None:
    state = SessionState()
    state.store_scan_results(
        [],
        baseline_findings=[
            _finding(tmp_path, "baseline-1", "RULE-BASE", 3, Severity.MEDIUM, FindingStatus.BASELINED),
        ],
    )
    state.set_current_view("findings-baselined")

    sarif = json.loads(render_current_view_sarif(state))

    invocation = sarif["runs"][0]["invocations"][0]["properties"]
    assert invocation["view_id"] == "findings-baselined"
    assert invocation["view_title"] == "Baselined findings"
    assert invocation["findings"] == 1
    assert sarif["runs"][0]["results"][0]["properties"]["status"] == "baselined"


def test_render_current_view_text_mentions_selection(tmp_path: Path) -> None:
    state = SessionState()
    state.store_scan_results(
        [],
        suppressed_findings=[
            _finding(tmp_path, "suppressed-1", "RULE-SUP", 4, Severity.HIGH, FindingStatus.SUPPRESSED),
        ],
    )
    state.set_current_view("suppression-review")

    text = render_current_view_text(state)

    assert "view: suppression-review" in text
    assert "title: Suppression review" in text
    assert "selected: HIGH suppressed-1" in text


def test_render_current_view_rules_exports_rule_browser() -> None:
    state = SessionState()
    state.set_current_view("rules")

    payload = json.loads(render_current_view_json(state))
    text = render_current_view_text(state)
    sarif = json.loads(render_current_view_sarif(state))

    assert payload["view"]["id"] == "rules"
    assert payload["view"]["title"] == "Rules"
    assert payload["current_view"]["rules"]
    assert payload["current_view"]["selected_rule"]["id"] == "SEC-SECRET-001"
    assert payload["rule_browser"]["pack_count"] == 1
    assert "Rules browser" in text
    assert "Selected pack: builtin-detectors@0.1.0" in text
    assert sarif["runs"][0]["invocations"][0]["properties"]["view_id"] == "rules"
    assert sarif["runs"][0]["tool"]["driver"]["rules"]


def test_render_current_view_rule_detail_exports_selected_rule() -> None:
    state = SessionState()
    state.set_current_view("rule-detail")

    payload = json.loads(render_current_view_json(state))
    text = render_current_view_text(state)
    sarif = json.loads(render_current_view_sarif(state))

    assert payload["view"]["id"] == "rule-detail"
    assert payload["view"]["title"] == "Rule detail"
    assert payload["rule_detail"]["selected_rule"]["id"] == "SEC-SECRET-001"
    assert payload["current_view"]["selected_rule"]["id"] == "SEC-SECRET-001"
    assert "Rule detail" in text
    assert "Rule ID: SEC-SECRET-001" in text
    assert sarif["runs"][0]["invocations"][0]["properties"]["view_id"] == "rule-detail"
    assert sarif["runs"][0]["invocations"][0]["properties"]["view_title"] == "Rule detail"
