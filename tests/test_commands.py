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


def test_command_registry_includes_rules_browser() -> None:
    registry = build_default_command_registry()

    rules_command = registry.resolve("/rulebook")
    rules_result = registry.execute("/rules")

    assert rules_command is not None
    assert rules_command.name == "/rules"
    assert rules_command.implemented is True
    assert rules_result.kind == "workspace"
    assert "Rules browser opened." in rules_result.message_lines[0]


def test_command_registry_includes_rule_pack_selection_commands() -> None:
    registry = build_default_command_registry()

    next_command = registry.resolve("/rule-next-pack")
    prev_command = registry.resolve("/rule-prev-pack")
    select_command = registry.resolve("/rule-select-pack")
    next_result = registry.execute("/rule-pack-next")
    prev_result = registry.execute("/rule-pack-prev")
    select_result = registry.execute("/rule-pack-select")

    assert next_command is not None
    assert next_command.name == "/rule-pack-next"
    assert prev_command is not None
    assert prev_command.name == "/rule-pack-prev"
    assert select_command is not None
    assert select_command.name == "/rule-pack-select"
    assert next_result.kind == "workspace"
    assert prev_result.kind == "workspace"
    assert select_result.kind == "workspace"
    assert select_result.prompt_steps[0].key == "pack"


def test_command_registry_includes_findings_search_and_filters() -> None:
    registry = build_default_command_registry()

    search_command = registry.resolve("/results-search")
    baseline_command = registry.resolve("/baseline-findings")
    suppression_command = registry.resolve("/suppressed-findings")
    severity_command = registry.resolve("/results-filter-severity")
    clear_command = registry.resolve("/results-clear-filters")
    triage_in_review_command = registry.resolve("/triage-open")
    triage_triaged_command = registry.resolve("/triage-resolve")
    triage_untriaged_command = registry.resolve("/triage-reset")
    search_result = registry.execute("/findings-search")
    baseline_result = registry.execute("/findings-baselined")
    suppression_result = registry.execute("/suppression-review")
    severity_result = registry.execute("/findings-filter-severity")
    clear_result = registry.execute("/findings-clear-filters")
    triage_in_review_result = registry.execute("/triage-in-review")
    triage_triaged_result = registry.execute("/triage-triaged")
    triage_untriaged_result = registry.execute("/triage-untriaged")

    assert search_command is not None
    assert search_command.name == "/findings-search"
    assert baseline_command is not None
    assert baseline_command.name == "/findings-baselined"
    assert suppression_command is not None
    assert suppression_command.name == "/suppression-review"
    assert severity_command is not None
    assert severity_command.name == "/findings-filter-severity"
    assert clear_command is not None
    assert clear_command.name == "/findings-clear-filters"
    assert triage_in_review_command is not None
    assert triage_in_review_command.name == "/triage-in-review"
    assert triage_triaged_command is not None
    assert triage_triaged_command.name == "/triage-triaged"
    assert triage_untriaged_command is not None
    assert triage_untriaged_command.name == "/triage-untriaged"
    assert search_result.kind == "workspace"
    assert search_result.prompt_steps[0].key == "query"
    assert baseline_result.kind == "workspace"
    assert "Open baselined findings." in baseline_result.message_lines[0]
    assert suppression_result.kind == "workspace"
    assert "Open suppression review." in suppression_result.message_lines[0]
    assert severity_result.kind == "workspace"
    assert severity_result.prompt_steps[0].key == "severity"
    assert clear_result.kind == "workspace"
    assert "Findings filters cleared." in clear_result.message_lines[0]
    assert triage_in_review_result.kind == "workspace"
    assert triage_in_review_result.prompt_steps[0].key == "reason"
    assert triage_triaged_result.kind == "workspace"
    assert triage_triaged_result.prompt_steps[0].key == "reason"
    assert triage_untriaged_result.kind == "workspace"
    assert "Reset the selected finding to untriaged." in triage_untriaged_result.message_lines[0]


def test_command_registry_includes_export_current_view_commands() -> None:
    registry = build_default_command_registry()

    export_json_command = registry.resolve("/export-current-json")
    export_sarif_command = registry.resolve("/export-current-sarif")
    export_json_result = registry.execute("/export-json")
    export_sarif_result = registry.execute("/export-sarif")

    assert export_json_command is not None
    assert export_json_command.name == "/export-json"
    assert export_sarif_command is not None
    assert export_sarif_command.name == "/export-sarif"
    assert export_json_result.kind == "export"
    assert export_sarif_result.kind == "export"


def test_command_history_tracks_recent_commands() -> None:
    history = CommandHistory(limit=3)

    history.add("/scan")
    history.add("/help")
    history.add("/scan-web")
    history.add("not a command")
    history.add("/exit")

    assert history.recent() == ("/exit", "/scan-web", "/help")
    assert history.previous() == "/scan-web"
