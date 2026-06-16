from mosec.state import SessionState


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
