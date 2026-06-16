from mosec.commands import CommandHistory, build_default_command_registry, normalize_command_text


def test_normalize_command_text_rejects_free_text() -> None:
    assert normalize_command_text("  /scan-quick  ") == "/scan-quick"
    assert normalize_command_text("scan quick") is None
    assert normalize_command_text("  /scan quick  ") is None
    assert normalize_command_text("help") is None


def test_command_registry_resolves_aliases_and_help() -> None:
    registry = build_default_command_registry()

    help_command = registry.resolve("/h")
    scan_command = registry.resolve("/quick-scan")

    assert help_command is not None
    assert help_command.name == "/help"
    assert scan_command is not None
    assert scan_command.name == "/scan-quick"

    help_lines = registry.help_lines()

    assert "MoSec commands" in help_lines[0]
    assert any("/scan-quick" in line for line in help_lines)
    assert any("/exit" in line for line in help_lines)


def test_command_registry_execute_help_and_unknown() -> None:
    registry = build_default_command_registry()

    help_result = registry.execute("/help")
    unknown_result = registry.execute("/scan quick")
    scan_result = registry.execute("/scan")

    assert help_result.kind == "help"
    assert "MoSec commands" in help_result.message_lines[0]
    assert unknown_result.kind == "invalid"
    assert "Commands must be exact slash commands." in unknown_result.message_lines[0]
    assert scan_result.kind == "wizard"
    assert len(scan_result.prompt_steps) == 3
    assert scan_result.prompt_steps[0].key == "target"
    assert scan_result.prompt_steps[1].choices == ("quick", "deep", "web", "mobile", "secrets", "sca", "policy")


def test_command_registry_requires_confirmation_for_exit_and_clear() -> None:
    registry = build_default_command_registry()

    exit_result = registry.execute("/exit")
    clear_result = registry.execute("/clear")

    assert exit_result.kind == "confirm"
    assert exit_result.confirmation is not None
    assert exit_result.confirmation.question == "Exit MoSec"
    assert exit_result.confirmation.action == "exit"
    assert clear_result.kind == "confirm"
    assert clear_result.confirmation is not None
    assert clear_result.confirmation.question == "Clear the terminal surface"
    assert clear_result.confirmation.action == "clear"


def test_command_registry_includes_repeat_last_scan() -> None:
    registry = build_default_command_registry()

    repeat_command = registry.resolve("/repeat-last-scan")
    repeat_result = registry.execute("/scan-repeat")

    assert repeat_command is not None
    assert repeat_command.name == "/scan-repeat"
    assert repeat_result.kind == "scan"


def test_command_registry_includes_scan_compare() -> None:
    registry = build_default_command_registry()

    compare_command = registry.resolve("/compare-last-scan")
    compare_result = registry.execute("/scan-compare")

    assert compare_command is not None
    assert compare_command.name == "/scan-compare"
    assert compare_result.kind == "scan"


def test_command_registry_includes_finding_detail_view() -> None:
    registry = build_default_command_registry()

    detail_command = registry.resolve("/finding")
    detail_result = registry.execute("/finding-detail")

    assert detail_command is not None
    assert detail_command.name == "/finding-detail"
    assert detail_result.kind == "workspace"


def test_command_history_tracks_recent_commands() -> None:
    history = CommandHistory(limit=3)

    history.add("/scan")
    history.add("/help")
    history.add("/scan-web")
    history.add("not a command")
    history.add("/exit")

    assert history.recent() == ("/exit", "/scan-web", "/help")
    assert history.previous() == "/scan-web"
