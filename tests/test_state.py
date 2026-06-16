from pathlib import Path

from mosec.state import SessionState
from mosec.findings import CodeLocation, Confidence, Finding, Severity


def test_session_state_tracks_workspace_mode_and_last_scan() -> None:
    state = SessionState()

    state.remember_command("/scan-web")
    state.record_scan(target="./fixtures", mode="web", output_format="json")

    assert state.workspace == "./fixtures"
    assert state.scan_mode == "web"
    assert state.output_format == "json"
    assert state.last_scan_target == "./fixtures"
    assert state.last_scan_mode == "web"
    assert state.last_scan_format == "json"
    assert state.last_command == "/scan-web"


def test_session_state_prompt_defaults_follow_current_state() -> None:
    state = SessionState(workspace="~/src", scan_mode="deep", output_format="sarif")

    prompts = state.scan_prompt_specs()

    assert prompts[0].default == "~/src"
    assert prompts[1].default == "deep"
    assert prompts[2].default == "sarif"


def test_session_state_summary_lines_cover_last_scan() -> None:
    state = SessionState(workspace="~/src", scan_mode="web", output_format="sarif")

    lines = state.summary_lines()

    assert "Session state" in lines[0]
    assert "Status [INFO]: Ready" in lines
    assert "Workspace: ~/src" in lines
    assert "Current mode: web" in lines
    assert "Output format: sarif" in lines
    assert "Last scan: none" in lines


def test_session_state_can_repeat_last_scan() -> None:
    state = SessionState()
    state.record_scan(target="./fixtures", mode="web", output_format="json")
    state.workspace = "./other"
    state.scan_mode = "deep"
    state.output_format = "text"

    repeated = state.repeat_last_scan()

    assert repeated is True
    assert state.workspace == "./fixtures"
    assert state.scan_mode == "web"
    assert state.output_format == "json"


def test_session_state_can_compare_current_to_last_scan() -> None:
    state = SessionState()
    state.record_scan(target="./fixtures", mode="web", output_format="json")
    state.workspace = "./other"
    state.scan_mode = "deep"
    state.output_format = "sarif"

    comparison = state.compare_current_to_last_scan()

    assert comparison is not None
    assert "Scan comparison" in comparison[0]
    assert "Target changed: yes" in comparison
    assert "Mode changed: yes" in comparison
    assert "Format changed: yes" in comparison


def test_session_state_can_store_and_select_findings() -> None:
    state = SessionState()
    findings = [
        Finding(
            id="one",
            rule_id="RULE-1",
            title="Critical issue",
            message="critical",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            location=CodeLocation(path=Path("app.py"), start_line=1),
            category="test",
        ),
        Finding(
            id="two",
            rule_id="RULE-2",
            title="Low issue",
            message="low",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            location=CodeLocation(path=Path("app.py"), start_line=2),
            category="test",
        ),
    ]

    state.store_findings(findings)

    assert len(state.findings) == 2
    assert state.selected_finding() is not None
    assert state.selected_finding().title == "Critical issue"


def test_session_state_filters_findings_by_query_and_severity() -> None:
    state = SessionState()
    findings = [
        Finding(
            id="one",
            rule_id="RULE-1",
            title="Critical issue",
            message="critical",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            location=CodeLocation(path=Path("app.py"), start_line=1),
            category="test",
        ),
        Finding(
            id="two",
            rule_id="RULE-2",
            title="High issue",
            message="high",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            location=CodeLocation(path=Path("service.py"), start_line=2),
            category="test",
        ),
        Finding(
            id="three",
            rule_id="RULE-3",
            title="Info note",
            message="info",
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            location=CodeLocation(path=Path("notes.py"), start_line=3),
            category="test",
        ),
    ]

    state.store_findings(findings)
    state.set_findings_search_query("issue")
    state.set_findings_severity_filters(["critical", "high"])

    filtered = state.filtered_findings()
    summary = state.findings_filter_summary()

    assert len(filtered) == 2
    assert [finding.rule_id for finding in filtered] == ["RULE-1", "RULE-2"]
    assert "Search query: issue" in summary
    assert "Severity filters: critical, high" in summary
    assert "Visible findings: 2 / 3" in summary

    state.clear_findings_filters()

    assert state.findings_search_query is None
    assert state.findings_severity_filters == []
    assert state.filtered_findings() == findings
