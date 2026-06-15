from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .sources import (
    SourceKind,
    is_auth_context_reference,
    is_body_source_reference,
    is_cookie_source_reference,
    is_header_source_reference,
    is_query_source_reference,
)


REQUEST_INPUT_MARKERS: tuple[str, ...] = (
    "$request->input(",
    "request()->input(",
    "$request->all(",
    "$request->post(",
    "$request->json(",
    "request('",
    "request.input(",
)


_ASSIGNMENT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\s*(?:const|let|var|val|final|String|int|long|double|float|boolean|bool|char|Object|auto)\s+(?P<target>[A-Za-z_$][\w$]*)\s*=\s*(?P<expr>.+?);?\s*$", re.IGNORECASE),
    re.compile(r"^\s*(?P<target>[A-Za-z_][\w$]*)\s*=\s*(?P<expr>.+?);?\s*$"),
    re.compile(r"^\s*\$(?P<target>[A-Za-z_][\w$]*)\s*=\s*(?P<expr>.+?);?\s*$"),
)

_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_CONTAINER_LITERAL_PATTERN = re.compile(r"^\s*[\[\{].*[\]\}]\s*$")
_PYTHON_FUNCTION_PATTERN = re.compile(r"^\s*def\s+(?P<name>[A-Za-z_][\w]*)\s*\((?P<params>[^)]*)\)\s*:\s*$")
_JS_FUNCTION_PATTERN = re.compile(
    r"^\s*(?:function\s+(?P<fn_name>[A-Za-z_$][\w$]*)\s*\((?P<fn_params>[^)]*)\)\s*\{|(?:const|let|var)\s+(?P<var_name>[A-Za-z_$][\w$]*)\s*=\s*(?:function\s*)?\((?P<var_params>[^)]*)\)\s*=>?\s*\{?)",
    re.IGNORECASE,
)
_CALL_PATTERN = re.compile(r"(?P<name>[A-Za-z_][\w]*)\s*\((?P<args>.*)\)")
_CONTAINER_WRITE_PATTERN = re.compile(r"^\s*(?P<container>[A-Za-z_$][\w$]*)\s*\[[^\]]+\]\s*=\s*(?P<expr>.+?);?\s*$")
_CONTAINER_READ_ASSIGNMENT_PATTERN = re.compile(
    r"^\s*(?:const|let|var|val|final|String|int|long|double|float|boolean|bool|char|Object|auto)?\s*(?P<target>[A-Za-z_$][\w$]*)\s*=\s*(?P<container>[A-Za-z_$][\w$]*)\s*\[[^\]]+\]\s*;?\s*$",
    re.IGNORECASE,
)
_CONTAINER_METHOD_PATTERN = re.compile(
    r"^\s*(?P<container>[A-Za-z_$][\w$]*)\.(?P<method>append|push|insert|extend)\((?P<args>.*)\)\s*;?\s*$",
    re.IGNORECASE,
)
_FIELD_WRITE_PATTERN = re.compile(
    r"^\s*(?P<field>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)\s*=\s*(?P<expr>.+?);?\s*$"
)
_FIELD_READ_ASSIGNMENT_PATTERN = re.compile(
    r"^\s*(?:const|let|var|val|final|String|int|long|double|float|boolean|bool|char|Object|auto)?\s*(?P<target>[A-Za-z_$][\w$]*)\s*=\s*(?P<field>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)\s*;?\s*$",
    re.IGNORECASE,
)
_FIELD_REFERENCE_PATTERN = re.compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+")
_PYTHON_BRANCH_PATTERN = re.compile(r"^\s*(?P<kind>if|elif|else)\b.*:\s*$")
_JS_BRANCH_PATTERN = re.compile(r"^\s*(?P<kind>if|else\s+if|else|switch|case)\b")
_FALSE_BRANCH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^\s*if\s+false\s*:\s*$", re.IGNORECASE),
    re.compile(r"^\s*if\s*\(\s*false\s*\)\s*\{?\s*$", re.IGNORECASE),
    re.compile(r"^\s*if\s*\(\s*0\s*\)\s*\{?\s*$", re.IGNORECASE),
    re.compile(r"^\s*switch\s*\(\s*false\s*\)\s*\{?\s*$", re.IGNORECASE),
    re.compile(r"^\s*switch\s*\(\s*0\s*\)\s*\{?\s*$", re.IGNORECASE),
)
_STRING_ESCAPE_SANITIZER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("html_escape", re.compile(r"^(?:html|markupsafe|cgi|flask|django\.utils\.html)\.escape\((?P<arg>.+)\)$", re.IGNORECASE)),
    ("html_escape", re.compile(r"^(?:escapeHtml|escape_html|lodash\.escape|_\.escape|he\.encode)\((?P<arg>.+)\)$", re.IGNORECASE)),
)
_URL_ALLOWLIST_GUARD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "url_allowlist",
        re.compile(r"(?:is_allowed_url|isAllowedUrl|is_safe_url|isSafeUrl|url_is_allowed|urlIsAllowed|allowed_url|allowlisted_url|is_trusted_url|isTrustedUrl)\((?P<arg>.+)\)", re.IGNORECASE),
    ),
    (
        "url_allowlist",
        re.compile(
            r"(?P<subject>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s+in\s+(?P<allowlist>(?:ALLOWED|TRUSTED|SAFE|ALLOWLISTED)_[A-Za-z_][\w$]*)",
            re.IGNORECASE,
        ),
    ),
)


@dataclass(slots=True, frozen=True)
class TaintLineage:
    variable: str
    source_kind: str
    source_expression: str
    source_line: int
    propagated_from: str | None = None
    propagated_from_line: int | None = None
    propagated_from_expression: str | None = None
    propagation_kind: str | None = None
    propagated_via_call: str | None = None
    sanitized: bool = False
    sanitizer_kind: str | None = None
    sanitizer_call: str | None = None
    guarded: bool = False
    guard_kind: str | None = None
    guard_call: str | None = None
    guard_line: int | None = None
    reachability: str | None = None
    path: tuple[str, ...] = field(default_factory=tuple)
    exploitability_context: dict[str, Any] = field(default_factory=dict)
    branch_context: bool = False
    branch_kind: str | None = None
    branch_line: int | None = None
    taint_chain: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "variable": self.variable,
            "source_kind": self.source_kind,
            "source_expression": self.source_expression,
            "source_line": self.source_line,
            "propagated_from": self.propagated_from,
            "propagated_from_line": self.propagated_from_line,
            "propagated_from_expression": self.propagated_from_expression,
            "propagation_kind": self.propagation_kind,
            "propagated_via_call": self.propagated_via_call,
            "sanitized": self.sanitized,
            "sanitizer_kind": self.sanitizer_kind,
            "sanitizer_call": self.sanitizer_call,
            "guarded": self.guarded,
            "guard_kind": self.guard_kind,
            "guard_call": self.guard_call,
            "guard_line": self.guard_line,
            "reachability": self.reachability,
            "path": list(self.path),
            "exploitability_context": dict(self.exploitability_context),
            "branch_context": self.branch_context,
            "branch_kind": self.branch_kind,
            "branch_line": self.branch_line,
            "taint_chain": list(self.taint_chain),
        }


@dataclass(slots=True, frozen=True)
class TaintState:
    lineages: dict[str, TaintLineage] = field(default_factory=dict)
    lineage_history_by_variable: dict[str, list[TaintLineage]] = field(default_factory=dict)
    tainted_variables_by_line: dict[int, list[str]] = field(default_factory=dict)
    scoped_lineages_by_line: dict[int, list[TaintLineage]] = field(default_factory=dict)
    field_lineages: dict[str, TaintLineage] = field(default_factory=dict)
    guarded_lines_by_line: dict[int, tuple[str, str | None, int]] = field(default_factory=dict)

    def tainted_variables(self) -> set[str]:
        return set(self.lineages)

    def lineage_for(self, variable: str | None) -> TaintLineage | None:
        if variable is None:
            return None
        return self.lineages.get(_normalize_identifier(variable))

    def lineage_for_line(self, variable: str | None, line_no: int | None) -> TaintLineage | None:
        if variable is None:
            return None
        normalized = _normalize_identifier(variable)
        history = self.lineage_history_by_variable.get(normalized)
        if not history:
            return self.lineages.get(normalized)
        if line_no is None:
            return history[-1]
        for lineage in reversed(history):
            if lineage.source_line <= line_no:
                return lineage
        return history[-1]

    def lineages_for_line(self, line_no: int) -> list[TaintLineage]:
        scoped = list(self.scoped_lineages_by_line.get(line_no, []))
        scoped.extend(self.lineages[name] for name in self.tainted_variables_by_line.get(line_no, []) if name in self.lineages)
        return scoped

    def field_lineage_for(self, value: str | None) -> TaintLineage | None:
        if value is None:
            return None
        return self.field_lineages.get(_normalize_identifier(value))

    def guard_context_for_line(self, line_no: int | None) -> tuple[str, str | None, int] | None:
        if line_no is None:
            return None
        return self.guarded_lines_by_line.get(line_no)


@dataclass(slots=True, frozen=True)
class FunctionDefinition:
    name: str
    parameters: tuple[str, ...]
    start_line: int
    end_line: int
    return_lines: tuple[int, ...] = field(default_factory=tuple)


@dataclass(slots=True, frozen=True)
class ReturnStatement:
    line: int
    expression: str


def _normalize_identifier(value: str) -> str:
    return value.lower().lstrip("$")


def _normalize_field_path(value: str) -> str:
    return ".".join(_normalize_identifier(part) for part in value.split(".") if part)


def _identifier_tokens(value: str) -> list[str]:
    seen: set[str] = set()
    tokens: list[str] = []
    for token in _IDENTIFIER_PATTERN.findall(value):
        normalized = _normalize_identifier(token)
        if normalized in seen:
            continue
        seen.add(normalized)
        tokens.append(normalized)
    return tokens


def _infer_direct_source_kind(expr: str) -> str | None:
    if is_query_source_reference(expr):
        return SourceKind.QUERY.value
    if is_body_source_reference(expr):
        return SourceKind.BODY.value
    if is_cookie_source_reference(expr):
        return SourceKind.COOKIES.value
    if is_header_source_reference(expr):
        return SourceKind.HEADERS.value
    if is_auth_context_reference(expr):
        return SourceKind.AUTH_CONTEXT.value
    lowered = expr.lower()
    if any(marker in lowered for marker in REQUEST_INPUT_MARKERS):
        return SourceKind.REQUEST_INPUT.value
    return None


def _infer_container_literal(expr: str) -> bool:
    lowered = expr.strip().lower()
    return bool(_CONTAINER_LITERAL_PATTERN.match(expr)) or lowered.startswith(("list(", "dict(", "array(", "new array(", "new map(", "map("))


def _extract_assignment(line: str) -> tuple[str, str] | None:
    lowered = line.strip().lower()
    if not lowered or lowered.startswith(("return ", "if ", "elif ", "else:", "for ", "while ", "def ", "class ", "import ", "from ", "try:", "except ", "with ")):
        return None
    if "==" in lowered or "!=" in lowered or "<=" in lowered or ">=" in lowered or ":=" in lowered:
        return None
    for pattern in _ASSIGNMENT_PATTERNS:
        match = pattern.match(line)
        if match is None:
            continue
        target = match.group("target")
        expr = match.group("expr").strip()
        if not target or not expr:
            continue
        return _normalize_identifier(target), expr
    return None


def _extract_container_write(line: str) -> tuple[str, str] | None:
    match = _CONTAINER_WRITE_PATTERN.match(line)
    if match is None:
        return None
    return _normalize_identifier(match.group("container")), match.group("expr").strip()


def _extract_container_read_assignment(line: str) -> tuple[str, str] | None:
    match = _CONTAINER_READ_ASSIGNMENT_PATTERN.match(line)
    if match is None:
        return None
    return _normalize_identifier(match.group("target")), _normalize_identifier(match.group("container"))


def _extract_container_method(line: str) -> tuple[str, str] | None:
    match = _CONTAINER_METHOD_PATTERN.match(line)
    if match is None:
        return None
    args = _split_arguments(match.group("args"))
    if not args:
        return None
    return _normalize_identifier(match.group("container")), args[0]


def _extract_field_write(line: str) -> tuple[str, str] | None:
    match = _FIELD_WRITE_PATTERN.match(line)
    if match is None:
        return None
    return _normalize_field_path(match.group("field")), match.group("expr").strip()


def _extract_field_read_assignment(line: str) -> tuple[str, str] | None:
    match = _FIELD_READ_ASSIGNMENT_PATTERN.match(line)
    if match is None:
        return None
    return _normalize_identifier(match.group("target")), _normalize_field_path(match.group("field"))


def _extract_field_references(line: str) -> list[str]:
    seen: set[str] = set()
    fields: list[str] = []
    for match in _FIELD_REFERENCE_PATTERN.findall(line):
        normalized = _normalize_field_path(match)
        if normalized in seen:
            continue
        seen.add(normalized)
        fields.append(normalized)
    return fields


def _extract_string_escape_sanitizer(expr: str) -> tuple[str, str, str] | None:
    stripped = expr.strip().rstrip(";")
    for sanitizer_kind, pattern in _STRING_ESCAPE_SANITIZER_PATTERNS:
        match = pattern.match(stripped)
        if match is None:
            continue
        argument = match.group("arg").strip()
        call_name = stripped.split("(", 1)[0].strip()
        return argument, sanitizer_kind, call_name
    return None


def is_string_escape_sanitized_expression(expr: str | None) -> bool:
    if expr is None:
        return False
    return _extract_string_escape_sanitizer(expr) is not None


def _extract_url_allowlist_guard(expr: str) -> tuple[str, str | None, str] | None:
    stripped = expr.strip().rstrip(";")
    lowered = stripped.lower()
    if "allow" not in lowered and "trust" not in lowered and "safe" not in lowered:
        return None
    for guard_kind, pattern in _URL_ALLOWLIST_GUARD_PATTERNS:
        match = pattern.search(stripped)
        if match is None:
            continue
        guard_call = match.group(0).strip()
        if "(" in guard_call:
            guard_call = guard_call.split("(", 1)[0].strip()
        return guard_kind, guard_call or None, stripped
    return None


def is_url_allowlist_guard_expression(expr: str | None) -> bool:
    if expr is None:
        return False
    return _extract_url_allowlist_guard(expr) is not None


def _branch_reachability(line: str | None) -> str:
    if line is None:
        return "unknown"
    stripped = line.strip()
    if any(pattern.match(stripped) for pattern in _FALSE_BRANCH_PATTERNS):
        return "unreachable"
    return "reachable"


def _record_lineage(
    lineages: dict[str, TaintLineage],
    lineage_history_by_variable: dict[str, list[TaintLineage]],
    target: str,
    lineage: TaintLineage,
) -> None:
    lineages[target] = lineage
    lineage_history_by_variable.setdefault(target, []).append(lineage)


def _find_python_branch_contexts(lines: list[str]) -> dict[int, tuple[str, int]]:
    contexts: dict[int, tuple[str, int]] = {}
    active: list[tuple[int, int, str]] = []
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        indent = len(line) - len(line.lstrip(" "))
        active = [context for context in active if indent > context[0]]
        for _, branch_line, branch_kind in active:
            contexts[index] = (branch_kind, branch_line)
        match = _PYTHON_BRANCH_PATTERN.match(line)
        if match is not None:
            active.append((indent, index, match.group("kind")))
    return contexts


def _find_javascript_branch_contexts(lines: list[str]) -> dict[int, tuple[str, int]]:
    contexts: dict[int, tuple[str, int]] = {}
    active: list[tuple[int, str]] = []
    brace_balance = 0
    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        while active and brace_balance <= 0:
            active.pop()
        for branch_line, branch_kind in active:
            contexts[index] = (branch_kind, branch_line)
        match = _JS_BRANCH_PATTERN.match(stripped)
        current_delta = stripped.count("{") - stripped.count("}")
        if match is not None and "{" in stripped:
            active.append((index, match.group("kind").replace(" ", "_")))
        brace_balance += current_delta
        if brace_balance <= 0:
            active.clear()
            brace_balance = 0
    return contexts


def _find_branch_contexts(lines: list[str]) -> dict[int, tuple[str, int]]:
    contexts = _find_python_branch_contexts(lines)
    for line_no, value in _find_javascript_branch_contexts(lines).items():
        contexts.setdefault(line_no, value)
    return contexts


def _branch_metadata(
    line_no: int,
    branch_contexts: dict[int, tuple[str, int]],
    origin: TaintLineage | None = None,
    lines: list[str] | None = None,
) -> dict[str, Any]:
    guard_meta: dict[str, Any] = {
        "guarded": False,
        "guard_kind": None,
        "guard_call": None,
        "guard_line": None,
    }
    reachability = "reachable"
    if line_no in branch_contexts:
        kind, branch_line = branch_contexts[line_no]
        if lines is not None and 0 < branch_line <= len(lines):
            branch_header = lines[branch_line - 1]
            reachability = _branch_reachability(branch_header)
            guard = _extract_url_allowlist_guard(branch_header)
            if guard is not None:
                guard_kind, guard_call, _ = guard
                guard_meta = {
                    "guarded": True,
                    "guard_kind": guard_kind,
                    "guard_call": guard_call,
                    "guard_line": branch_line,
                }
        return {
            "branch_context": True,
            "branch_kind": kind,
            "branch_line": branch_line,
            "reachability": reachability,
            **guard_meta,
        }
    if origin is not None and origin.branch_context:
        return {
            "branch_context": True,
            "branch_kind": origin.branch_kind,
            "branch_line": origin.branch_line,
            "reachability": origin.reachability or "reachable",
            "guarded": origin.guarded,
            "guard_kind": origin.guard_kind,
            "guard_call": origin.guard_call,
            "guard_line": origin.guard_line,
        }
    return {
        "branch_context": False,
        "branch_kind": None,
        "branch_line": None,
        "reachability": reachability,
        **guard_meta,
    }


def _parse_parameters(raw: str) -> tuple[str, ...]:
    parameters: list[str] = []
    for value in raw.split(","):
        candidate = value.strip()
        if not candidate:
            continue
        candidate = candidate.split("=", 1)[0].strip()
        candidate = candidate.lstrip("$")
        if not candidate:
            continue
        normalized = _normalize_identifier(candidate)
        if normalized and normalized not in parameters:
            parameters.append(normalized)
    return tuple(parameters)


def _find_python_functions(lines: list[str]) -> list[FunctionDefinition]:
    functions: list[FunctionDefinition] = []
    for index, line in enumerate(lines, start=1):
        match = _PYTHON_FUNCTION_PATTERN.match(line)
        if match is None:
            continue
        indent = len(line) - len(line.lstrip(" "))
        end_line = len(lines)
        for inner_index in range(index, len(lines)):
            candidate = lines[inner_index]
            if not candidate.strip():
                continue
            candidate_indent = len(candidate) - len(candidate.lstrip(" "))
            if candidate_indent <= indent:
                end_line = inner_index
                break
        return_lines = tuple(
            inner_index + 1
            for inner_index in range(index, min(end_line, len(lines)))
            if lines[inner_index].lstrip().startswith("return ")
        )
        functions.append(
            FunctionDefinition(
                name=_normalize_identifier(match.group("name")),
                parameters=_parse_parameters(match.group("params")),
                start_line=index + 1,
                end_line=end_line,
                return_lines=return_lines,
            )
        )
    return functions


def _find_javascript_functions(lines: list[str]) -> list[FunctionDefinition]:
    functions: list[FunctionDefinition] = []
    for index, line in enumerate(lines, start=1):
        match = _JS_FUNCTION_PATTERN.match(line)
        if match is None:
            continue
        name = match.group("fn_name") or match.group("var_name")
        raw_params = match.group("fn_params") or match.group("var_params") or ""
        brace_balance = line.count("{") - line.count("}")
        end_line = index
        for inner_index in range(index, len(lines)):
            if inner_index == index:
                if brace_balance <= 0:
                    break
                continue
            brace_balance += lines[inner_index].count("{") - lines[inner_index].count("}")
            if brace_balance <= 0:
                end_line = inner_index + 1
                break
        return_lines = tuple(
            inner_index + 1
            for inner_index in range(index, min(end_line or len(lines), len(lines)))
            if "return " in lines[inner_index]
        )
        functions.append(
            FunctionDefinition(
                name=_normalize_identifier(name),
                parameters=_parse_parameters(raw_params),
                start_line=index + 1,
                end_line=end_line or len(lines),
                return_lines=return_lines,
            )
        )
    return functions


def _extract_return_statement(line: str, line_no: int) -> ReturnStatement | None:
    stripped = line.strip()
    if not stripped.startswith("return "):
        return None
    expression = stripped[len("return ") :].strip().rstrip(";")
    if not expression:
        return None
    return ReturnStatement(line=line_no, expression=expression)


def _split_arguments(raw: str) -> list[str]:
    arguments: list[str] = []
    current: list[str] = []
    depth = 0
    for character in raw:
        if character == "," and depth == 0:
            candidate = "".join(current).strip()
            if candidate:
                arguments.append(candidate)
            current = []
            continue
        if character in "([{":
            depth += 1
        elif character in ")]}" and depth > 0:
            depth -= 1
        current.append(character)
    candidate = "".join(current).strip()
    if candidate:
        arguments.append(candidate)
    return arguments


def _extract_call(line: str) -> tuple[str, list[str]] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith(("def ", "function ", "class ", "if ", "for ", "while ")):
        return None
    match = _CALL_PATTERN.search(stripped)
    if match is None:
        return None
    return _normalize_identifier(match.group("name")), _split_arguments(match.group("args"))


def _extract_named_calls(line: str, function_names: set[str]) -> list[tuple[str, list[str]]]:
    stripped = line.strip()
    if not stripped:
        return []

    calls: list[tuple[str, list[str]]] = []
    for function_name in sorted(function_names, key=len, reverse=True):
        needle = f"{function_name}("
        search_start = 0
        lowered = stripped.lower()
        while True:
            index = lowered.find(needle, search_start)
            if index == -1:
                break
            depth = 0
            argument_start = index + len(needle)
            position = argument_start
            while position < len(stripped):
                character = stripped[position]
                if character == "(":
                    depth += 1
                elif character == ")":
                    if depth == 0:
                        arguments = stripped[argument_start:position]
                        calls.append((function_name, _split_arguments(arguments)))
                        break
                    depth -= 1
                position += 1
            search_start = index + len(needle)
    return calls


def _find_functions(lines: list[str]) -> list[FunctionDefinition]:
    functions = _find_python_functions(lines)
    functions.extend(_find_javascript_functions(lines))
    return functions


def _resolve_origin_from_expression(
    expr: str,
    line_no: int,
    lineages: dict[str, TaintLineage],
    scoped_lineages_by_line: dict[int, list[TaintLineage]],
    field_lineages: dict[str, TaintLineage] | None = None,
) -> TaintLineage | None:
    sanitizer = _extract_string_escape_sanitizer(expr)
    if sanitizer is not None:
        inner_expr, sanitizer_kind, sanitizer_call = sanitizer
        origin = _resolve_origin_from_expression(inner_expr, line_no, lineages, scoped_lineages_by_line, field_lineages)
        if origin is None:
            return None
        return TaintLineage(
            variable=origin.variable,
            source_kind=origin.source_kind,
            source_expression=origin.source_expression,
            source_line=origin.source_line,
            propagated_from=origin.propagated_from,
            propagated_from_line=origin.propagated_from_line,
            propagated_from_expression=origin.propagated_from_expression,
            propagation_kind=origin.propagation_kind,
            propagated_via_call=origin.propagated_via_call,
            sanitized=True,
            sanitizer_kind=sanitizer_kind,
            sanitizer_call=sanitizer_call,
            guarded=origin.guarded,
            guard_kind=origin.guard_kind,
            guard_call=origin.guard_call,
            guard_line=origin.guard_line,
            reachability=origin.reachability,
            path=origin.path,
            exploitability_context=origin.exploitability_context,
            branch_context=origin.branch_context,
            branch_kind=origin.branch_kind,
            branch_line=origin.branch_line,
            taint_chain=origin.taint_chain,
        )

    direct_kind = _infer_direct_source_kind(expr)
    if direct_kind is not None:
        return TaintLineage(
            variable=_normalize_identifier(expr),
            source_kind=direct_kind,
            source_expression=expr,
            source_line=line_no,
            taint_chain=(),
        )

    scoped = list(scoped_lineages_by_line.get(line_no, []))
    if field_lineages is None:
        field_lineages = {}
    for field_token in _extract_field_references(expr):
        if field_token in field_lineages:
            return field_lineages[field_token]
    tokens = _identifier_tokens(expr)
    for token in tokens:
        for lineage in scoped:
            if lineage.variable == token:
                return lineage
        if token in lineages:
            return lineages[token]
    return None


def build_assignment_taint_state(lines: list[str]) -> TaintState:
    lineages: dict[str, TaintLineage] = {}
    lineage_history_by_variable: dict[str, list[TaintLineage]] = {}
    tainted_variables_by_line: dict[int, list[str]] = {}
    scoped_lineages_by_line: dict[int, list[TaintLineage]] = {}
    field_lineages: dict[str, TaintLineage] = {}
    guarded_lines_by_line: dict[int, tuple[str, str | None, int]] = {}
    branch_contexts = _find_branch_contexts(lines)
    for line_no, (branch_kind, branch_line) in branch_contexts.items():
        if 0 < branch_line <= len(lines):
            guard = _extract_url_allowlist_guard(lines[branch_line - 1])
            if guard is not None:
                guard_kind, guard_call, _ = guard
                guarded_lines_by_line[line_no] = (guard_kind, guard_call, branch_line)

    for line_no, raw_line in enumerate(lines, start=1):
        extracted = _extract_assignment(raw_line)
        if extracted is None:
            continue
        target, expr = extracted
        matched_origin = _resolve_origin_from_expression(expr, line_no, lineages, scoped_lineages_by_line, field_lineages)
        lineage: TaintLineage | None = None
        if matched_origin is not None:
            branch_meta = _branch_metadata(line_no, branch_contexts, matched_origin, lines)
            lineage = TaintLineage(
                variable=target,
                source_kind=matched_origin.source_kind,
                source_expression=matched_origin.source_expression,
                source_line=matched_origin.source_line,
                propagated_from=matched_origin.variable if matched_origin.variable != _normalize_identifier(expr) else None,
                propagated_from_line=matched_origin.propagated_from_line or matched_origin.source_line,
                propagated_from_expression=matched_origin.propagated_from_expression or matched_origin.source_expression,
                propagation_kind="assignment",
                propagated_via_call=matched_origin.propagated_via_call,
                sanitized=matched_origin.sanitized,
                sanitizer_kind=matched_origin.sanitizer_kind,
                sanitizer_call=matched_origin.sanitizer_call,
                guarded=branch_meta["guarded"],
                guard_kind=branch_meta["guard_kind"],
                guard_call=branch_meta["guard_call"],
                guard_line=branch_meta["guard_line"],
                reachability=branch_meta["reachability"],
                path=(f"{matched_origin.source_expression}@{matched_origin.source_line}", f"{target}@{line_no}"),
                exploitability_context={
                    "source_kind": matched_origin.source_kind,
                    "source_line": matched_origin.source_line,
                    "sink_line": line_no,
                    "sink_variable": target,
                    "reachability": branch_meta["reachability"],
                    "guarded": branch_meta["guarded"],
                    "branch_context": branch_meta["branch_context"],
                },
                branch_context=branch_meta["branch_context"],
                branch_kind=branch_meta["branch_kind"],
                branch_line=branch_meta["branch_line"],
                taint_chain=(matched_origin.taint_chain + (target,)) if matched_origin.taint_chain else (target,),
            )

        if lineage is None:
            continue

        _record_lineage(lineages, lineage_history_by_variable, target, lineage)
        tainted_variables_by_line.setdefault(line_no, []).append(target)

    functions = {function.name: function for function in _find_functions(lines)}
    call_parameter_lineages: list[tuple[int, FunctionDefinition, TaintLineage]] = []
    for line_no, raw_line in enumerate(lines, start=1):
        for function_name, arguments in _extract_named_calls(raw_line, set(functions)):
            function = functions.get(function_name)
            if function is None or not function.parameters:
                continue
            for index, parameter in enumerate(function.parameters):
                if index >= len(arguments):
                    break
                argument = arguments[index]
                origin = _resolve_origin_from_expression(argument, line_no, lineages, scoped_lineages_by_line, field_lineages)
                if origin is None:
                    continue

                branch_meta = _branch_metadata(line_no, branch_contexts, origin, lines)
                lineage = TaintLineage(
                    variable=parameter,
                    source_kind=origin.source_kind,
                    source_expression=origin.source_expression,
                    source_line=origin.source_line,
                    propagated_from=origin.variable,
                    propagated_from_line=origin.propagated_from_line or origin.source_line,
                    propagated_from_expression=origin.propagated_from_expression or origin.source_expression,
                    propagation_kind="function_call",
                    propagated_via_call=function.name,
                    sanitized=origin.sanitized,
                    sanitizer_kind=origin.sanitizer_kind,
                    sanitizer_call=origin.sanitizer_call,
                    guarded=branch_meta["guarded"],
                    guard_kind=branch_meta["guard_kind"],
                    guard_call=branch_meta["guard_call"],
                    guard_line=branch_meta["guard_line"],
                    reachability=branch_meta["reachability"],
                    path=(f"{origin.source_expression}@{origin.source_line}", f"{parameter}@{line_no}"),
                    exploitability_context={
                        "source_kind": origin.source_kind,
                        "source_line": origin.source_line,
                        "sink_line": line_no,
                        "sink_variable": parameter,
                        "reachability": branch_meta["reachability"],
                        "guarded": branch_meta["guarded"],
                        "branch_context": branch_meta["branch_context"],
                    },
                    branch_context=branch_meta["branch_context"],
                    branch_kind=branch_meta["branch_kind"],
                    branch_line=branch_meta["branch_line"],
                    taint_chain=origin.taint_chain + (parameter,),
                )
                call_parameter_lineages.append((line_no, function, lineage))
                for scoped_line in range(function.start_line, function.end_line + 1):
                    scoped_lineages_by_line.setdefault(scoped_line, []).append(lineage)

    for call_line, function, parameter_lineage in call_parameter_lineages:
        local_lineages: dict[str, TaintLineage] = {parameter_lineage.variable: parameter_lineage}
        return_lineage: TaintLineage | None = None
        for scoped_line in range(function.start_line, function.end_line + 1):
            raw_line = lines[scoped_line - 1]
            extracted_assignment = _extract_assignment(raw_line)
            if extracted_assignment is not None:
                target, expr = extracted_assignment
                origin = next((local_lineages[token] for token in _identifier_tokens(expr) if token in local_lineages), None)
                if origin is not None:
                    branch_meta = _branch_metadata(scoped_line, branch_contexts, origin, lines)
                    local_lineages[target] = TaintLineage(
                        variable=target,
                        source_kind=origin.source_kind,
                        source_expression=origin.source_expression,
                        source_line=origin.source_line,
                        propagated_from=origin.variable,
                        propagated_from_line=origin.propagated_from_line or origin.source_line,
                        propagated_from_expression=origin.propagated_from_expression or origin.source_expression,
                        propagation_kind="assignment",
                        propagated_via_call=origin.propagated_via_call,
                        sanitized=origin.sanitized,
                        sanitizer_kind=origin.sanitizer_kind,
                        sanitizer_call=origin.sanitizer_call,
                        guarded=branch_meta["guarded"],
                        guard_kind=branch_meta["guard_kind"],
                        guard_call=branch_meta["guard_call"],
                        guard_line=branch_meta["guard_line"],
                        reachability=branch_meta["reachability"],
                        path=(f"{origin.source_expression}@{origin.source_line}", f"{target}@{scoped_line}"),
                        exploitability_context={
                            "source_kind": origin.source_kind,
                            "source_line": origin.source_line,
                            "sink_line": scoped_line,
                            "sink_variable": target,
                            "reachability": branch_meta["reachability"],
                            "guarded": branch_meta["guarded"],
                            "branch_context": branch_meta["branch_context"],
                        },
                        branch_context=branch_meta["branch_context"],
                        branch_kind=branch_meta["branch_kind"],
                        branch_line=branch_meta["branch_line"],
                        taint_chain=origin.taint_chain + (target,),
                    )

            return_stmt = _extract_return_statement(raw_line, scoped_line)
            if return_stmt is None:
                continue
            origin = _resolve_origin_from_expression(return_stmt.expression, scoped_line, local_lineages, scoped_lineages_by_line, field_lineages)
            if origin is not None:
                branch_meta = _branch_metadata(scoped_line, branch_contexts, origin, lines)
                return_lineage = TaintLineage(
                    variable=function.name,
                    source_kind=origin.source_kind,
                    source_expression=origin.source_expression,
                    source_line=origin.source_line,
                    propagated_from=origin.variable,
                    propagated_from_line=origin.propagated_from_line or origin.source_line,
                    propagated_from_expression=origin.propagated_from_expression or origin.source_expression,
                    propagation_kind="return_value",
                    propagated_via_call=function.name,
                    sanitized=origin.sanitized,
                    sanitizer_kind=origin.sanitizer_kind,
                    sanitizer_call=origin.sanitizer_call,
                    guarded=branch_meta["guarded"],
                    guard_kind=branch_meta["guard_kind"],
                    guard_call=branch_meta["guard_call"],
                    guard_line=branch_meta["guard_line"],
                    reachability=branch_meta["reachability"],
                    path=(f"{origin.source_expression}@{origin.source_line}", f"{function.name}@{scoped_line}"),
                    exploitability_context={
                        "source_kind": origin.source_kind,
                        "source_line": origin.source_line,
                        "sink_line": scoped_line,
                        "sink_variable": function.name,
                        "reachability": branch_meta["reachability"],
                        "guarded": branch_meta["guarded"],
                        "branch_context": branch_meta["branch_context"],
                    },
                    branch_context=branch_meta["branch_context"],
                    branch_kind=branch_meta["branch_kind"],
                    branch_line=branch_meta["branch_line"],
                    taint_chain=origin.taint_chain + (function.name,),
                )
                break

        if return_lineage is None:
            continue

        scoped_lineages_by_line.setdefault(call_line, []).append(return_lineage)
        extracted_assignment = _extract_assignment(lines[call_line - 1])
        if extracted_assignment is not None:
            target, expr = extracted_assignment
            if expr.lower().startswith(f"{function.name}("):
                branch_meta = _branch_metadata(call_line, branch_contexts, return_lineage, lines)
                caller_lineage = TaintLineage(
                    variable=target,
                    source_kind=return_lineage.source_kind,
                    source_expression=return_lineage.source_expression,
                    source_line=return_lineage.source_line,
                    propagated_from=return_lineage.variable,
                    propagated_from_line=return_lineage.propagated_from_line or return_lineage.source_line,
                    propagated_from_expression=return_lineage.propagated_from_expression or return_lineage.source_expression,
                    propagation_kind="return_value",
                    propagated_via_call=function.name,
                    sanitized=return_lineage.sanitized,
                    sanitizer_kind=return_lineage.sanitizer_kind,
                    sanitizer_call=return_lineage.sanitizer_call,
                    guarded=branch_meta["guarded"],
                    guard_kind=branch_meta["guard_kind"],
                    guard_call=branch_meta["guard_call"],
                    guard_line=branch_meta["guard_line"],
                    reachability=branch_meta["reachability"],
                    path=tuple(return_lineage.path) + (f"{target}@{call_line}",),
                    exploitability_context={**return_lineage.exploitability_context, "sink_line": call_line, "sink_variable": target, "reachability": branch_meta["reachability"], "guarded": branch_meta["guarded"], "branch_context": branch_meta["branch_context"]},
                    branch_context=branch_meta["branch_context"],
                    branch_kind=branch_meta["branch_kind"],
                    branch_line=branch_meta["branch_line"],
                    taint_chain=return_lineage.taint_chain + (target,),
                )
                _record_lineage(lineages, lineage_history_by_variable, target, caller_lineage)
                tainted_variables_by_line.setdefault(call_line, []).append(target)

    for line_no, raw_line in enumerate(lines, start=1):
        extracted_assignment = _extract_assignment(raw_line)
        if extracted_assignment is not None:
            target, expr = extracted_assignment
            if _infer_container_literal(expr):
                origin = _resolve_origin_from_expression(expr, line_no, lineages, scoped_lineages_by_line, field_lineages)
                if origin is not None:
                    branch_meta = _branch_metadata(line_no, branch_contexts, origin, lines)
                    _record_lineage(
                        lineages,
                        lineage_history_by_variable,
                        target,
                        TaintLineage(
                        variable=target,
                        source_kind=origin.source_kind,
                        source_expression=origin.source_expression,
                        source_line=origin.source_line,
                        propagated_from=origin.variable,
                        propagated_from_line=origin.propagated_from_line or origin.source_line,
                        propagated_from_expression=origin.propagated_from_expression or origin.source_expression,
                        propagation_kind="container",
                        propagated_via_call=origin.propagated_via_call,
                        sanitized=origin.sanitized,
                        sanitizer_kind=origin.sanitizer_kind,
                        sanitizer_call=origin.sanitizer_call,
                        guarded=branch_meta["guarded"],
                        guard_kind=branch_meta["guard_kind"],
                        guard_call=branch_meta["guard_call"],
                        guard_line=branch_meta["guard_line"],
                        reachability=branch_meta["reachability"],
                        path=(f"{origin.source_expression}@{origin.source_line}", f"{target}@{line_no}"),
                        exploitability_context={
                            "source_kind": origin.source_kind,
                            "source_line": origin.source_line,
                            "sink_line": line_no,
                            "sink_variable": target,
                            "reachability": branch_meta["reachability"],
                            "guarded": branch_meta["guarded"],
                            "branch_context": branch_meta["branch_context"],
                        },
                        branch_context=branch_meta["branch_context"],
                        branch_kind=branch_meta["branch_kind"],
                        branch_line=branch_meta["branch_line"],
                        taint_chain=origin.taint_chain + (target,),
                    ),
                    )
                    tainted_variables_by_line.setdefault(line_no, []).append(target)

        extracted_write = _extract_container_write(raw_line)
        if extracted_write is not None:
            container, expr = extracted_write
            origin = _resolve_origin_from_expression(expr, line_no, lineages, scoped_lineages_by_line, field_lineages)
            if origin is not None:
                branch_meta = _branch_metadata(line_no, branch_contexts, origin, lines)
                _record_lineage(
                    lineages,
                    lineage_history_by_variable,
                    container,
                    TaintLineage(
                    variable=container,
                    source_kind=origin.source_kind,
                    source_expression=origin.source_expression,
                    source_line=origin.source_line,
                    propagated_from=origin.variable,
                    propagated_from_line=origin.propagated_from_line or origin.source_line,
                    propagated_from_expression=origin.propagated_from_expression or origin.source_expression,
                    propagation_kind="container",
                    propagated_via_call=origin.propagated_via_call,
                    sanitized=origin.sanitized,
                    sanitizer_kind=origin.sanitizer_kind,
                    sanitizer_call=origin.sanitizer_call,
                    guarded=branch_meta["guarded"],
                    guard_kind=branch_meta["guard_kind"],
                    guard_call=branch_meta["guard_call"],
                    guard_line=branch_meta["guard_line"],
                    reachability=branch_meta["reachability"],
                    path=(f"{origin.source_expression}@{origin.source_line}", f"{container}@{line_no}"),
                    exploitability_context={
                        "source_kind": origin.source_kind,
                        "source_line": origin.source_line,
                        "sink_line": line_no,
                        "sink_variable": container,
                        "reachability": branch_meta["reachability"],
                        "guarded": branch_meta["guarded"],
                        "branch_context": branch_meta["branch_context"],
                    },
                    branch_context=branch_meta["branch_context"],
                    branch_kind=branch_meta["branch_kind"],
                    branch_line=branch_meta["branch_line"],
                    taint_chain=origin.taint_chain + (container,),
                ),
                )
                tainted_variables_by_line.setdefault(line_no, []).append(container)

        extracted_method = _extract_container_method(raw_line)
        if extracted_method is not None:
            container, expr = extracted_method
            origin = _resolve_origin_from_expression(expr, line_no, lineages, scoped_lineages_by_line, field_lineages)
            if origin is not None:
                branch_meta = _branch_metadata(line_no, branch_contexts, origin, lines)
                _record_lineage(
                    lineages,
                    lineage_history_by_variable,
                    container,
                    TaintLineage(
                    variable=container,
                    source_kind=origin.source_kind,
                    source_expression=origin.source_expression,
                    source_line=origin.source_line,
                    propagated_from=origin.variable,
                    propagated_from_line=origin.propagated_from_line or origin.source_line,
                    propagated_from_expression=origin.propagated_from_expression or origin.source_expression,
                    propagation_kind="container",
                    propagated_via_call=origin.propagated_via_call,
                    sanitized=origin.sanitized,
                    sanitizer_kind=origin.sanitizer_kind,
                    sanitizer_call=origin.sanitizer_call,
                    guarded=branch_meta["guarded"],
                    guard_kind=branch_meta["guard_kind"],
                    guard_call=branch_meta["guard_call"],
                    guard_line=branch_meta["guard_line"],
                    reachability=branch_meta["reachability"],
                    path=(f"{origin.source_expression}@{origin.source_line}", f"{container}@{line_no}"),
                    exploitability_context={
                        "source_kind": origin.source_kind,
                        "source_line": origin.source_line,
                        "sink_line": line_no,
                        "sink_variable": container,
                        "reachability": branch_meta["reachability"],
                        "guarded": branch_meta["guarded"],
                        "branch_context": branch_meta["branch_context"],
                    },
                    branch_context=branch_meta["branch_context"],
                    branch_kind=branch_meta["branch_kind"],
                    branch_line=branch_meta["branch_line"],
                    taint_chain=origin.taint_chain + (container,),
                ),
                )
                tainted_variables_by_line.setdefault(line_no, []).append(container)

        extracted_read = _extract_container_read_assignment(raw_line)
        if extracted_read is not None:
            target, container = extracted_read
            origin = lineages.get(container)
            if origin is not None:
                branch_meta = _branch_metadata(line_no, branch_contexts, origin)
                _record_lineage(
                    lineages,
                    lineage_history_by_variable,
                    target,
                    TaintLineage(
                    variable=target,
                    source_kind=origin.source_kind,
                    source_expression=origin.source_expression,
                    source_line=origin.source_line,
                    propagated_from=origin.variable,
                    propagated_from_line=origin.propagated_from_line or origin.source_line,
                    propagated_from_expression=origin.propagated_from_expression or origin.source_expression,
                    propagation_kind="container",
                    propagated_via_call=origin.propagated_via_call,
                    sanitized=origin.sanitized,
                    sanitizer_kind=origin.sanitizer_kind,
                    sanitizer_call=origin.sanitizer_call,
                    branch_context=branch_meta["branch_context"],
                    branch_kind=branch_meta["branch_kind"],
                    branch_line=branch_meta["branch_line"],
                    taint_chain=origin.taint_chain + (target,),
                ),
                )
                tainted_variables_by_line.setdefault(line_no, []).append(target)

        extracted_field_write = _extract_field_write(raw_line)
        if extracted_field_write is not None:
            field_name, expr = extracted_field_write
            origin = _resolve_origin_from_expression(expr, line_no, lineages, scoped_lineages_by_line, field_lineages)
            if origin is not None:
                branch_meta = _branch_metadata(line_no, branch_contexts, origin, lines)
                field_lineages[field_name] = TaintLineage(
                    variable=field_name,
                    source_kind=origin.source_kind,
                    source_expression=origin.source_expression,
                    source_line=origin.source_line,
                    propagated_from=origin.variable,
                    propagated_from_line=origin.propagated_from_line or origin.source_line,
                    propagated_from_expression=origin.propagated_from_expression or origin.source_expression,
                    propagation_kind="field",
                    propagated_via_call=origin.propagated_via_call,
                    sanitized=origin.sanitized,
                    sanitizer_kind=origin.sanitizer_kind,
                    sanitizer_call=origin.sanitizer_call,
                    guarded=branch_meta["guarded"],
                    guard_kind=branch_meta["guard_kind"],
                    guard_call=branch_meta["guard_call"],
                    guard_line=branch_meta["guard_line"],
                    reachability=branch_meta["reachability"],
                    path=(f"{origin.source_expression}@{origin.source_line}", f"{target}@{line_no}"),
                    exploitability_context={
                        "source_kind": origin.source_kind,
                        "source_line": origin.source_line,
                        "sink_line": line_no,
                        "sink_variable": target,
                        "reachability": branch_meta["reachability"],
                        "guarded": branch_meta["guarded"],
                        "branch_context": branch_meta["branch_context"],
                    },
                    branch_context=branch_meta["branch_context"],
                    branch_kind=branch_meta["branch_kind"],
                    branch_line=branch_meta["branch_line"],
                    taint_chain=origin.taint_chain + (field_name,),
                )

        extracted_field_read = _extract_field_read_assignment(raw_line)
        if extracted_field_read is not None:
            target, field_name = extracted_field_read
            origin = field_lineages.get(field_name)
            if origin is not None:
                branch_meta = _branch_metadata(line_no, branch_contexts, origin, lines)
                _record_lineage(
                    lineages,
                    lineage_history_by_variable,
                    target,
                    TaintLineage(
                    variable=target,
                    source_kind=origin.source_kind,
                    source_expression=origin.source_expression,
                    source_line=origin.source_line,
                    propagated_from=origin.variable,
                    propagated_from_line=origin.propagated_from_line or origin.source_line,
                    propagated_from_expression=origin.propagated_from_expression or origin.source_expression,
                    propagation_kind="field",
                    propagated_via_call=origin.propagated_via_call,
                    sanitized=origin.sanitized,
                    sanitizer_kind=origin.sanitizer_kind,
                    sanitizer_call=origin.sanitizer_call,
                    guarded=branch_meta["guarded"],
                    guard_kind=branch_meta["guard_kind"],
                    guard_call=branch_meta["guard_call"],
                    guard_line=branch_meta["guard_line"],
                    reachability=branch_meta["reachability"],
                    path=(f"{origin.source_expression}@{origin.source_line}", f"{target}@{line_no}"),
                    exploitability_context={
                        "source_kind": origin.source_kind,
                        "source_line": origin.source_line,
                        "sink_line": line_no,
                        "sink_variable": target,
                        "reachability": branch_meta["reachability"],
                        "guarded": branch_meta["guarded"],
                        "branch_context": branch_meta["branch_context"],
                    },
                    branch_context=branch_meta["branch_context"],
                    branch_kind=branch_meta["branch_kind"],
                    branch_line=branch_meta["branch_line"],
                    taint_chain=origin.taint_chain + (target,),
                ),
                )
                tainted_variables_by_line.setdefault(line_no, []).append(target)

    return TaintState(
        lineages=lineages,
        lineage_history_by_variable=lineage_history_by_variable,
        tainted_variables_by_line=tainted_variables_by_line,
        scoped_lineages_by_line=scoped_lineages_by_line,
        field_lineages=field_lineages,
        guarded_lines_by_line=guarded_lines_by_line,
    )


def line_uses_tainted_flow(line: str, state: TaintState | None, line_no: int | None = None) -> list[TaintLineage]:
    if state is None or (not state.lineages and not state.scoped_lineages_by_line and not state.field_lineages):
        return []
    tokens = _identifier_tokens(line)
    field_tokens = _extract_field_references(line)
    matched: list[TaintLineage] = []
    scoped = state.lineages_for_line(line_no) if line_no is not None else []
    for field_token in field_tokens:
        lineage = state.field_lineage_for(field_token)
        if lineage is not None and lineage not in matched:
            matched.append(lineage)
    for token in tokens:
        for lineage in scoped:
            if lineage.variable == token and lineage not in matched:
                matched.append(lineage)
        lineage = state.lineage_for_line(token, line_no)
        if lineage is not None and lineage not in matched:
            matched.append(lineage)
    return matched


def line_uses_tainted_assignment(line: str, state: TaintState | None) -> list[TaintLineage]:
    return line_uses_tainted_flow(line, state)


def taint_propagation_metadata(line: str, state: TaintState | None, line_no: int | None = None) -> dict[str, Any]:
    matched = line_uses_tainted_flow(line, state, line_no)
    if not matched:
        return {}
    primary = matched[0]
    return {
        "taint_propagation": primary.propagation_kind or "assignment",
        "tainted_variables": [lineage.variable for lineage in matched],
        "taint_source_kind": primary.source_kind,
        "taint_source_expression": primary.source_expression,
        "taint_source_line": primary.source_line,
        "taint_origin_variable": primary.propagated_from,
        "taint_origin_line": primary.propagated_from_line,
        "taint_origin_expression": primary.propagated_from_expression,
        "taint_call": primary.propagated_via_call,
        "taint_sanitized": primary.sanitized,
        "taint_sanitizer_kind": primary.sanitizer_kind,
        "taint_sanitizer_call": primary.sanitizer_call,
        "taint_guarded": primary.guarded or bool(state.guard_context_for_line(line_no)),
        "taint_guard_kind": primary.guard_kind or (state.guard_context_for_line(line_no)[0] if state.guard_context_for_line(line_no) is not None else None),
        "taint_guard_call": primary.guard_call or (state.guard_context_for_line(line_no)[1] if state.guard_context_for_line(line_no) is not None else None),
        "taint_guard_line": primary.guard_line or (state.guard_context_for_line(line_no)[2] if state.guard_context_for_line(line_no) is not None else None),
        "taint_reachability": primary.reachability or "reachable",
        "taint_path": list(primary.path),
        "taint_sink_line": line_no,
        "taint_exploitability_context": {
            **primary.exploitability_context,
            "sink_line": line_no,
            "sink_expression": line.strip(),
            "reachability": primary.reachability or "reachable",
            "branch_context": primary.branch_context,
            "guarded": primary.guarded or bool(state.guard_context_for_line(line_no)),
        },
        "taint_branch_context": primary.branch_context,
        "taint_branch_kind": primary.branch_kind,
        "taint_branch_line": primary.branch_line,
        "taint_chain": list(primary.taint_chain),
    }


def assignment_propagation_metadata(line: str, state: TaintState | None) -> dict[str, Any]:
    return taint_propagation_metadata(line, state)
