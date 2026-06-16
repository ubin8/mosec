from mosec.tui import launch_home_screen, render_home_screen


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


def test_launch_home_screen_finding_detail_shows_empty_state(capsys) -> None:
    def fake_input(prompt: str) -> str:
        return "/finding-detail"

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Finding detail view" in output
    assert "No finding selected." in output
    assert "Status [INFO]: Finding detail view opened." in output


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
