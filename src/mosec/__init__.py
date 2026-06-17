"""MoSec CLI package."""

from .findings import (
    CodeLocation,
    CodeSymbolReference,
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    Severity,
    TriageStatus,
)
from .audit import AuditEntry
from .commands import CommandOutcome, CommandRegistry, CommandSpec, PromptSpec, build_default_command_registry, normalize_command_text
from .ir import IRAssignment, IRCall, IRDocument, IRLiteral, IRLocation, IRMemberAccess
from .rules import MatchStrategy, Rule, RuleCategory, RulePack, RulePattern, RuleTarget
from .state import SessionState
from .taint import TaintLineage, TaintState, assignment_propagation_metadata, build_assignment_taint_state, is_string_escape_sanitized_expression, is_url_allowlist_guard_expression, line_uses_tainted_assignment, line_uses_tainted_flow, taint_propagation_metadata
from .sources import AUTH_CONTEXT_SOURCE_MARKERS, AUTH_GUARD_MARKERS, BODY_SOURCE_MARKERS, COOKIE_SOURCE_MARKERS, HEADER_SOURCE_MARKERS, QUERY_SOURCE_MARKERS, ROLE_GUARD_MARKERS, SourceKind, USER_INPUT_SOURCE_KINDS, is_auth_context_reference, is_auth_guard_reference, is_body_source_reference, is_cookie_source_reference, is_header_source_reference, is_query_source_reference, is_role_guard_reference, is_user_input_source_kind
from .reporting import render_current_view_json, render_current_view_sarif, render_current_view_text
from .rule_browser import (
    build_builtin_rule_packs,
    render_rule_browser_json,
    render_rule_browser_lines,
    render_rule_browser_sarif,
    render_rule_detail_json,
    render_rule_detail_lines,
    render_rule_detail_sarif,
    rule_browser_lines,
    rule_browser_payload,
    rule_browser_sarif,
)
from .tui import launch_home_screen, render_home_screen

__version__ = "0.1.0"
