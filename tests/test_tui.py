from mosec.cli import main
from mosec.tui import render_home_screen


def test_render_home_screen_contains_logo_and_navigation() -> None:
    screen = render_home_screen(width=96)

    assert "████" in screen or "███" in screen
    assert "MoSec  Healthy" not in screen
    assert "CLI-first application security scanner" not in screen
    assert "Scan | Rules | Reports | Mobile | Settings" not in screen
    assert "Type `s` for a quick scan hint" not in screen
    assert " >" in screen


def test_main_without_arguments_prints_home_screen(capsys) -> None:
    exit_code = main([])
    output = capsys.readouterr().out

    assert exit_code == 0
    assert "MoSec" in output
    assert "Type `s` for a quick scan hint" in output
