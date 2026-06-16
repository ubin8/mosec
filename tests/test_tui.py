from pathlib import Path

from mosec.findings import CodeLocation, Confidence, Finding, Severity
from mosec.state import SessionState
from mosec.tui import (
    _apply_findings_workspace_change,
    _apply_triage_workspace_change,
    _baseline_findings_view_lines,
    _finding_detail_lines,
    _findings_view_lines,
    _suppression_review_view_lines,
    launch_home_screen,
    render_home_screen,
)


def test_render_home_screen_contains_logo_and_navigation() -> None:
    screen = render_home_screen(width=96, height=36)

    assert "MOSEC" in screen or "███" in screen
    assert "▄█████▄" in screen
    assert "MoSec  Healthy" not in screen
    assert "CLI-first application security scanner" not in screen
    assert "Scan | Rules | Reports | Mobile | Settings" not in screen
    assert "Type `s` for a quick scan hint" not in screen
    assert "Status [INFO]: Ready" in screen
    assert ">" not in screen
    assert screen.startswith("\n")


def test_launch_home_screen_interactive_renders_prompt_dock(capsys) -> None:
    prompts: list[str] = []
    responses = iter(["/scan", "./fixtures", "web", "json"])

    def fake_input(prompt: str) -> str:
        prompts.append(prompt)
        return next(responses)

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert prompts[0] == ""
    assert any(prompt.startswith("Target path") for prompt in prompts[1:])
    assert any(prompt.startswith("Scan mode") for prompt in prompts[1:])
    assert any(prompt.startswith("Output format") for prompt in prompts[1:])
    assert "▄█████▄" in output
    assert "> " in output
    assert "Guided scan configured." in output
    assert "Target: ./fixtures" in output
    assert "Mode: web" in output
    assert "Format: json" in output
    assert "Status [SUCCESS]: Guided scan prepared for ./fixtures" in output
    lines = output.splitlines()
    assert lines.count("─" * 96) >= 2


def test_launch_home_screen_quick_scan_prepares_state(capsys) -> None:
    def fake_input(prompt: str) -> str:
        return "/scan-quick"

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Quick scan prepared." in output
    assert "Scan progress" in output
    assert "Target: ." in output
    assert "Mode: quick" in output
    assert "Status: preparing detectors" in output
    assert "Format: text" in output
    assert "Status [SUCCESS]: Quick scan prepared for ." in output


def test_launch_home_screen_deep_scan_prepares_state(capsys) -> None:
    def fake_input(prompt: str) -> str:
        return "/scan-deep"

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Deep scan prepared." in output
    assert "Target: ." in output
    assert "Mode: deep" in output
    assert "Format: text" in output
    assert "Status [SUCCESS]: Deep scan prepared for ." in output


def test_launch_home_screen_web_scan_prepares_state(capsys) -> None:
    def fake_input(prompt: str) -> str:
        return "/scan-web"

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Web scan prepared." in output
    assert "Target: ." in output
    assert "Mode: web" in output
    assert "Format: text" in output
    assert "Status [SUCCESS]: Web scan prepared for ." in output


def test_launch_home_screen_mobile_scan_prepares_state(capsys) -> None:
    def fake_input(prompt: str) -> str:
        return "/scan-mobile"

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Mobile scan prepared." in output
    assert "Target: ." in output
    assert "Mode: mobile" in output
    assert "Format: text" in output
    assert "Status [SUCCESS]: Mobile scan prepared for ." in output


def test_launch_home_screen_secrets_scan_prepares_state(capsys) -> None:
    def fake_input(prompt: str) -> str:
        return "/scan-secrets"

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Secrets scan prepared." in output
    assert "Target: ." in output
    assert "Mode: secrets" in output
    assert "Format: text" in output
    assert "Status [SUCCESS]: Secrets scan prepared for ." in output


def test_launch_home_screen_dependency_scan_prepares_state(capsys) -> None:
    def fake_input(prompt: str) -> str:
        return "/scan-sca"

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Sca scan prepared." in output
    assert "Target: ." in output
    assert "Mode: sca" in output
    assert "Format: text" in output
    assert "Status [SUCCESS]: Sca scan prepared for ." in output


def test_launch_home_screen_policy_scan_prepares_state(capsys) -> None:
    def fake_input(prompt: str) -> str:
        return "/scan-policy"

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Policy scan prepared." in output
    assert "Target: ." in output
    assert "Mode: policy" in output
    assert "Format: text" in output
    assert "Status [SUCCESS]: Policy scan prepared for ." in output


def test_launch_home_screen_repeat_last_scan_reports_missing_history(capsys) -> None:
    def fake_input(prompt: str) -> str:
        return "/scan-repeat"

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "No previous scan to repeat." in output
    assert "Status [WARNING]: No previous scan to repeat." in output


def test_launch_home_screen_compare_last_scan_reports_missing_history(capsys) -> None:
    def fake_input(prompt: str) -> str:
        return "/scan-compare"

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "No previous scan to compare." in output
    assert "Status [WARNING]: No previous scan to compare." in output


def test_launch_home_screen_findings_workspace_shows_empty_state(capsys) -> None:
    def fake_input(prompt: str) -> str:
        return "/findings"

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Findings workspace" in output
    assert "No scan results available yet." in output
    assert "Status [INFO]: Findings workspace opened." in output


def test_launch_home_screen_baselined_findings_workspace_shows_empty_state(capsys) -> None:
    def fake_input(prompt: str) -> str:
        return "/findings-baselined"

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Baselined findings workspace" in output
    assert "No baselined findings available yet." in output
    assert "Status [INFO]: Baselined findings workspace opened." in output


def test_launch_home_screen_findings_search_updates_workspace_state(capsys) -> None:
    prompts: list[str] = []
    responses = iter(["/findings-search", "issue"])

    def fake_input(prompt: str) -> str:
        prompts.append(prompt)
        return next(responses)

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert prompts[0] == ""
    assert "Search findings." in output
    assert "Findings search set to issue." in output
    assert "Status [SUCCESS]: Findings search set to issue." in output


def test_launch_home_screen_clears_findings_filters(capsys) -> None:
    def fake_input(prompt: str) -> str:
        return "/findings-clear-filters"

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Findings filters cleared." in output
    assert "Status [SUCCESS]: Findings filters cleared." in output


def test_findings_view_groups_by_severity() -> None:
    state = SessionState()
    state.store_findings(
        [
            Finding(
                id="critical-1",
                rule_id="RULE-1",
                title="Critical issue",
                message="critical",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                location=CodeLocation(path=Path("app.py"), start_line=1),
                category="test",
            ),
            Finding(
                id="high-1",
                rule_id="RULE-2",
                title="High issue",
                message="high",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                location=CodeLocation(path=Path("app.py"), start_line=2),
                category="test",
            ),
            Finding(
                id="low-1",
                rule_id="RULE-3",
                title="Low issue",
                message="low",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                location=CodeLocation(path=Path("app.py"), start_line=3),
                category="test",
            ),
        ]
    )

    lines = _findings_view_lines(state)

    assert "Active findings" in lines
    assert "Search query: none" in lines
    assert "Severity filters: all" in lines
    assert "Critical (1)" in lines
    assert "High (1)" in lines
    assert "Low (1)" in lines
    assert any("Critical issue" in line for line in lines)


def test_findings_view_includes_baselined_section() -> None:
    state = SessionState()
    state.store_scan_results(
        [
            Finding(
                id="active-1",
                rule_id="RULE-ACTIVE",
                title="Active issue",
                message="active",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                location=CodeLocation(path=Path("app.py"), start_line=1),
                category="test",
            )
        ],
        baseline_findings=[
            Finding(
                id="baseline-1",
                rule_id="RULE-BASELINE",
                title="Baselined issue",
                message="baseline",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                location=CodeLocation(path=Path("legacy.py"), start_line=4),
                category="test",
            )
        ],
    )

    lines = _findings_view_lines(state)

    assert "Active findings" in lines
    assert "Baselined findings" in lines
    assert "Baselined findings: 1" in state.summary_lines()
    assert any("Baselined issue" in line for line in lines)


def test_baselined_findings_view_lists_baselined_findings() -> None:
    state = SessionState()
    state.store_scan_results(
        [],
        baseline_findings=[
            Finding(
                id="baseline-1",
                rule_id="RULE-BASELINE",
                title="Baselined issue",
                message="baseline",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                location=CodeLocation(path=Path("legacy.py"), start_line=4),
                category="test",
            )
        ],
    )

    lines = _baseline_findings_view_lines(state)

    assert "Baselined findings workspace" in lines[0]
    assert "Baselined findings" in lines
    assert any("Baselined issue" in line for line in lines)


def test_launch_home_screen_finding_baselined_view_uses_baseline_section(capsys) -> None:
    def fake_input(prompt: str) -> str:
        return "/findings-baselined"

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Baselined findings workspace" in output
    assert "No baselined findings available yet." in output


def test_launch_home_screen_suppression_review_workspace_shows_empty_state(capsys) -> None:
    def fake_input(prompt: str) -> str:
        return "/suppression-review"

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Suppression review workspace" in output
    assert "No suppressed findings available yet." in output
    assert "Status [INFO]: Suppression review workspace opened." in output


def test_suppression_review_view_lists_suppressed_findings() -> None:
    state = SessionState()
    state.store_scan_results(
        [],
        suppressed_findings=[
            Finding(
                id="suppressed-1",
                rule_id="RULE-SUPPRESSED",
                title="Suppressed issue",
                message="suppressed",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                location=CodeLocation(path=Path("legacy.py"), start_line=8),
                category="test",
                metadata={"suppression_reason": "legacy exception"},
            )
        ],
    )

    lines = _suppression_review_view_lines(state)

    assert "Suppression review workspace" in lines[0]
    assert "Suppressed findings: 1" in lines
    assert any("Suppressed issue" in line for line in lines)
    assert any("source=suppression" in line for line in lines)


def test_findings_view_applies_search_and_severity_filters() -> None:
    state = SessionState()
    state.store_findings(
        [
            Finding(
                id="critical-1",
                rule_id="RULE-1",
                title="Critical issue",
                message="critical",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                location=CodeLocation(path=Path("app.py"), start_line=1),
                category="test",
            ),
            Finding(
                id="high-1",
                rule_id="RULE-2",
                title="High issue",
                message="high",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                location=CodeLocation(path=Path("app.py"), start_line=2),
                category="test",
            ),
            Finding(
                id="info-1",
                rule_id="RULE-3",
                title="Info note",
                message="info",
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                location=CodeLocation(path=Path("notes.py"), start_line=3),
                category="test",
            ),
        ]
    )

    state.set_findings_search_query("issue")
    state.set_findings_severity_filters(["high"])

    lines = _findings_view_lines(state)

    assert "Search query: issue" in lines
    assert "Severity filters: high" in lines
    assert "Visible findings: 1 / 3" in lines
    assert "High (1)" in lines
    assert any("High issue" in line for line in lines)
    assert "Critical (0)" in lines
    assert "Info (0)" in lines


def test_apply_findings_workspace_change_updates_search_and_filters() -> None:
    state = SessionState()
    state.store_findings(
        [
            Finding(
                id="critical-1",
                rule_id="RULE-1",
                title="Critical issue",
                message="critical",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                location=CodeLocation(path=Path("app.py"), start_line=1),
                category="test",
            ),
            Finding(
                id="high-1",
                rule_id="RULE-2",
                title="High issue",
                message="high",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                location=CodeLocation(path=Path("app.py"), start_line=2),
                category="test",
            ),
        ]
    )

    _apply_findings_workspace_change(state, "/findings-search", {"query": "issue"})
    _apply_findings_workspace_change(state, "/findings-filter-severity", {"severity": "high"})
    lines = _findings_view_lines(state)

    assert state.findings_search_query == "issue"
    assert state.findings_severity_filters == ["high"]
    assert "Search query: issue" in lines
    assert "Severity filters: high" in lines
    assert "Visible findings: 1 / 2" in lines

    _apply_findings_workspace_change(state, "/findings-clear-filters", {})

    assert state.findings_search_query is None
    assert state.findings_severity_filters == []
    assert "Search query: none" in _findings_view_lines(state)


def test_launch_home_screen_finding_detail_shows_empty_state(capsys) -> None:
    def fake_input(prompt: str) -> str:
        return "/finding-detail"

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Finding detail view" in output
    assert "No finding selected." in output
    assert "Status [INFO]: Finding detail view opened." in output


def test_finding_detail_view_shows_selected_finding() -> None:
    state = SessionState()
    state.store_findings(
        [
            Finding(
                id="critical-1",
                rule_id="RULE-1",
                title="Critical issue",
                message="critical",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                location=CodeLocation(path=Path("app.py"), start_line=1),
                category="test",
                remediation="Fix it",
            )
        ]
    )

    lines = _finding_detail_lines(state)

    assert "Finding detail view" in lines[0]
    assert "Selected: Critical issue" in lines
    assert "Severity: critical" in lines
    assert "Rule: RULE-1" in lines
    assert any("Fix it" in line for line in lines)


def test_finding_detail_view_shows_triage_actions() -> None:
    state = SessionState()
    state.store_findings(
        [
            Finding(
                id="critical-1",
                rule_id="RULE-1",
                title="Critical issue",
                message="critical",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                location=CodeLocation(path=Path("app.py"), start_line=1),
                category="test",
                triage_reason="manual review",
                triage_note="already checked",
            )
        ]
    )

    lines = _finding_detail_lines(state)

    assert any("Triage reason: manual review" in line for line in lines)
    assert any("Triage note: already checked" in line for line in lines)
    assert any("/triage-in-review" in line for line in lines)


def test_apply_triage_workspace_change_updates_selected_finding() -> None:
    state = SessionState()
    state.store_findings(
        [
            Finding(
                id="critical-1",
                rule_id="RULE-1",
                title="Critical issue",
                message="critical",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                location=CodeLocation(path=Path("app.py"), start_line=1),
                category="test",
            )
        ]
    )

    lines = _apply_triage_workspace_change(
        state,
        "/triage-in-review",
        {"reason": "needs manual verification", "note": "triaged from the UI"},
    )

    assert state.findings[0].triage_status.value == "in_review"
    assert state.findings[0].triage_reason == "needs manual verification"
    assert state.findings[0].triage_note == "triaged from the UI"
    assert "Finding marked as in review." in lines[0]
    assert any("Reason: needs manual verification" in line for line in lines)
    assert any("Note: triaged from the UI" in line for line in lines)


def test_apply_triage_workspace_change_resets_selected_finding() -> None:
    state = SessionState()
    state.store_findings(
        [
            Finding(
                id="critical-1",
                rule_id="RULE-1",
                title="Critical issue",
                message="critical",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                location=CodeLocation(path=Path("app.py"), start_line=1),
                category="test",
                triage_reason="needs review",
                triage_note="to be reset",
            )
        ]
    )

    lines = _apply_triage_workspace_change(state, "/triage-untriaged")

    assert state.findings[0].triage_status.value == "untriaged"
    assert state.findings[0].triage_reason is None
    assert state.findings[0].triage_note is None
    assert "Finding reset to untriaged." in lines[0]


def test_launch_home_screen_workspace_selection_updates_target(capsys) -> None:
    prompts: list[str] = []
    responses = iter(["/workspace", "./projects/mosec"])

    def fake_input(prompt: str) -> str:
        prompts.append(prompt)
        return next(responses)

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert prompts[0] == ""
    assert "Workspace target [.]: " in prompts[1]
    assert "Workspace selected." in output
    assert "Workspace: ./projects/mosec" in output
    assert "Status [SUCCESS]: Workspace set to ./projects/mosec" in output


def test_launch_home_screen_allows_scan_cancellation(capsys) -> None:
    prompts: list[str] = []
    responses = iter(["/scan", "/cancel"])

    def fake_input(prompt: str) -> str:
        prompts.append(prompt)
        return next(responses)

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert any(prompt.startswith("Target path") for prompt in prompts[1:])
    assert "Guided scan canceled." in output
    assert "Status [WARNING]: Guided scan canceled." in output


def test_launch_home_screen_requires_confirmation_for_exit(capsys) -> None:
    prompts: list[str] = []
    responses = iter(["/exit", "n"])

    def fake_input(prompt: str) -> str:
        prompts.append(prompt)
        return next(responses)

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert prompts[0] == ""
    assert "Exit MoSec [y/N]:" in prompts[1]
    assert "Action canceled." in output
    assert "Status [WARNING]: Action canceled." in output


def test_launch_home_screen_workspace_command_shows_session_state(capsys) -> None:
    prompts: list[str] = []
    responses = iter(["/workspace", "./projects/mosec"])

    def fake_input(prompt: str) -> str:
        prompts.append(prompt)
        return next(responses)

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert prompts[0] == ""
    assert "Status [INFO]: Ready" in output
    assert "Workspace target [.]: " in prompts[1]
    assert "Workspace selected." in output
    assert "Workspace: ./projects/mosec" in output
    assert "Status [SUCCESS]: Workspace set to ./projects/mosec" in output
