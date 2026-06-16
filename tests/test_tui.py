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
    assert "Target: ." in output
    assert "Mode: quick" in output
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
    def fake_input(prompt: str) -> str:
        return "/workspace"

    exit_code = launch_home_screen(width=96, height=36, interactive=True, input_func=fake_input)
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "Status [INFO]: Ready" in output
    assert "Session state" in output
    assert "Workspace: ." in output
    assert "Current mode: deep" in output
    assert "Output format: text" in output
    assert "Last scan: none" in output
