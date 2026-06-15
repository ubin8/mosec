from mosec import assignment_propagation_metadata, build_assignment_taint_state, is_string_escape_sanitized_expression, is_url_allowlist_guard_expression, line_uses_tainted_assignment, line_uses_tainted_flow, taint_propagation_metadata


def test_assignment_taint_tracks_aliases() -> None:
    lines = [
        "next_url = request.args.get('next')",
        "redirect_target = next_url",
        "return redirect(redirect_target)",
    ]

    state = build_assignment_taint_state(lines)

    assert state.lineage_for("next_url") is not None
    assert state.lineage_for("next_url").source_kind == "query"
    assert state.lineage_for("redirect_target") is not None
    assert state.lineage_for("redirect_target").source_kind == "query"
    assert state.lineage_for("redirect_target").propagated_from == "next_url"
    assert line_uses_tainted_assignment("return redirect(redirect_target)", state)

    metadata = assignment_propagation_metadata("return redirect(redirect_target)", state)

    assert metadata["taint_propagation"] == "assignment"
    assert metadata["taint_source_kind"] == "query"
    assert metadata["taint_origin_variable"] == "next_url"
    assert metadata["taint_chain"] == ["next_url", "redirect_target"]


def test_assignment_taint_handles_cross_language_aliases() -> None:
    lines = [
        "const nextUrl = req.body.url;",
        "const finalUrl = nextUrl;",
        "axios.get(finalUrl);",
    ]

    state = build_assignment_taint_state(lines)

    assert state.lineage_for("nexturl") is not None
    assert state.lineage_for("finalurl") is not None
    assert state.lineage_for("finalurl").source_kind == "body"
    assert state.lineage_for("finalurl").propagated_from == "nexturl"
    assert line_uses_tainted_assignment("axios.get(finalUrl);", state)


def test_function_call_taint_propagates_to_parameters() -> None:
    lines = [
        "def forward(target):",
        "    return redirect(target)",
        "next_url = request.args.get('next')",
        "forward(next_url)",
    ]

    state = build_assignment_taint_state(lines)

    matched = line_uses_tainted_flow("    return redirect(target)", state, 2)
    assert matched
    assert matched[0].variable == "target"
    assert matched[0].source_kind == "query"
    assert matched[0].propagation_kind == "function_call"
    assert matched[0].propagated_via_call == "forward"

    metadata = taint_propagation_metadata("    return redirect(target)", state, 2)
    assert metadata["taint_propagation"] == "function_call"
    assert metadata["taint_call"] == "forward"
    assert metadata["taint_source_kind"] == "query"


def test_return_value_taint_propagates_to_assignment_and_call_site() -> None:
    lines = [
        "def normalize(target):",
        "    alias = target",
        "    return alias",
        "next_url = request.args.get('next')",
        "redirect_target = normalize(next_url)",
        "return redirect(normalize(next_url))",
    ]

    state = build_assignment_taint_state(lines)

    assert state.lineage_for("redirect_target") is not None
    assert state.lineage_for("redirect_target").source_kind == "query"
    assert state.lineage_for("redirect_target").propagation_kind == "return_value"
    assert state.lineage_for("redirect_target").propagated_via_call == "normalize"

    call_site = line_uses_tainted_flow("return redirect(normalize(next_url))", state, 6)
    assert call_site
    assert any(lineage.propagation_kind == "return_value" for lineage in call_site)

    metadata = taint_propagation_metadata("return redirect(normalize(next_url))", state, 6)
    assert metadata["taint_propagation"] == "return_value"
    assert metadata["taint_call"] == "normalize"
    assert metadata["taint_source_kind"] == "query"


def test_container_taint_propagates_through_write_and_read() -> None:
    lines = [
        "items = []",
        "next_url = request.args.get('next')",
        "items.append(next_url)",
        "redirect_target = items[0]",
        "return redirect(redirect_target)",
    ]

    state = build_assignment_taint_state(lines)

    assert state.lineage_for("items") is not None
    assert state.lineage_for("items").propagation_kind == "container"
    assert state.lineage_for("redirect_target") is not None
    assert state.lineage_for("redirect_target").propagation_kind == "container"

    metadata = taint_propagation_metadata("return redirect(redirect_target)", state, 5)
    assert metadata["taint_propagation"] == "container"
    assert metadata["taint_source_kind"] == "query"


def test_container_literal_taint_propagates() -> None:
    lines = [
        "next_url = request.args.get('next')",
        "payload = {'next': next_url}",
        "redirect_target = payload['next']",
    ]

    state = build_assignment_taint_state(lines)

    assert state.lineage_for("payload") is not None
    assert state.lineage_for("payload").propagation_kind == "container"
    assert state.lineage_for("redirect_target") is not None
    assert state.lineage_for("redirect_target").source_kind == "query"


def test_field_taint_propagates_through_write_and_read() -> None:
    lines = [
        "payload = object()",
        "next_url = request.args.get('next')",
        "payload.next = next_url",
        "redirect_target = payload.next",
        "return redirect(redirect_target)",
    ]

    state = build_assignment_taint_state(lines)

    assert state.field_lineage_for("payload.next") is not None
    assert state.field_lineage_for("payload.next").propagation_kind == "field"
    assert state.lineage_for("redirect_target") is not None
    assert state.lineage_for("redirect_target").propagation_kind == "field"

    metadata = taint_propagation_metadata("return redirect(redirect_target)", state, 5)
    assert metadata["taint_propagation"] == "field"
    assert metadata["taint_source_kind"] == "query"


def test_field_taint_matches_direct_sink_usage() -> None:
    lines = [
        "next_url = request.args.get('next')",
        "payload.next = next_url",
        "return redirect(payload.next)",
    ]

    state = build_assignment_taint_state(lines)

    matched = line_uses_tainted_flow("return redirect(payload.next)", state, 3)
    assert matched
    assert any(lineage.propagation_kind == "field" for lineage in matched)


def test_branch_taint_is_kept_conservatively() -> None:
    lines = [
        "if condition:",
        "    redirect_target = request.args.get('next')",
        "else:",
        "    redirect_target = safe_default",
        "return redirect(redirect_target)",
    ]

    state = build_assignment_taint_state(lines)

    assert state.lineage_for("redirect_target") is not None
    assert state.lineage_for("redirect_target").source_kind == "query"
    assert state.lineage_for("redirect_target").branch_context is True
    assert state.lineage_for("redirect_target").branch_kind == "if"
    assert state.lineage_for("redirect_target").branch_line == 2

    metadata = taint_propagation_metadata("return redirect(redirect_target)", state, 5)
    assert metadata["taint_branch_context"] is True
    assert metadata["taint_branch_kind"] == "if"
    assert metadata["taint_branch_line"] == 2


def test_string_escape_sanitizer_marks_taint_lineage() -> None:
    lines = [
        "safe_name = html.escape(request.args.get('name'))",
        "return render_template(safe_name)",
    ]

    state = build_assignment_taint_state(lines)

    assert is_string_escape_sanitized_expression("html.escape(request.args.get('name'))") is True
    assert state.lineage_for("safe_name") is not None
    assert state.lineage_for("safe_name").sanitized is True
    assert state.lineage_for("safe_name").sanitizer_kind == "html_escape"
    assert state.lineage_for("safe_name").sanitizer_call == "html.escape"

    metadata = taint_propagation_metadata("return render_template(safe_name)", state, 2)
    assert metadata["taint_sanitized"] is True
    assert metadata["taint_sanitizer_kind"] == "html_escape"
    assert metadata["taint_sanitizer_call"] == "html.escape"


def test_url_allowlist_guard_marks_branch_lineage() -> None:
    lines = [
        "url = request.args.get('next')",
        "def go(url):",
        "    if is_allowed_url(url):",
        "        return redirect(url)",
    ]

    state = build_assignment_taint_state(lines)

    assert is_url_allowlist_guard_expression("is_allowed_url(url)") is True
    metadata = taint_propagation_metadata("        return redirect(url)", state, 4)
    assert metadata["taint_guarded"] is True
    assert metadata["taint_guard_kind"] == "url_allowlist"
    assert metadata["taint_guard_call"] == "is_allowed_url"
    assert metadata["taint_guard_line"] == 2


def test_reachability_marks_false_branch_as_unreachable() -> None:
    lines = [
        "if False:",
        "    next_url = request.args.get('next')",
        "    return redirect(next_url)",
    ]

    state = build_assignment_taint_state(lines)

    metadata = taint_propagation_metadata("    return redirect(next_url)", state, 3)

    assert metadata["taint_reachability"] == "unreachable"
    assert metadata["taint_sink_line"] == 3
    assert metadata["taint_exploitability_context"]["reachability"] == "unreachable"
    assert metadata["taint_exploitability_context"]["sink_line"] == 3
    assert metadata["taint_exploitability_context"]["branch_context"] is True
