from mosec.tui import launch_home_screen, render_home_screen


def test_render_home_screen_contains_logo_and_navigation() -> None:
    screen = render_home_screen(width=96, height=36)

    assert "MOSEC" in screen or "███" in screen
    assert "▄█████▄" in screen
    assert "MoSec  Healthy" not in screen
    assert "CLI-first application security scanner" not in screen
    assert "Scan | Rules | Reports | Mobile | Settings" not in screen
    assert "Type `s` for a quick scan hint" not in screen
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
    lines = output.splitlines()
    assert lines.count("─" * 96) >= 2
