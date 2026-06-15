from __future__ import annotations

from pathlib import Path
from typing import Any

from .findings import Confidence, Severity
from .rules import MatchStrategy, Rule, RuleCategory, RulePack, RulePattern, RuleTarget


class RulePackError(ValueError):
    pass


def _require_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RulePackError(f"field '{field_name}' must be a non-empty string")
    return value


def _require_list(value: Any, field_name: str) -> list[Any]:
    if not isinstance(value, list):
        raise RulePackError(f"field '{field_name}' must be a list")
    return value


def _parse_rule_target(value: Any) -> RuleTarget:
    if not isinstance(value, dict):
        raise RulePackError("target entries must be tables")
    language = _require_string(value.get("language"), "targets.language")
    framework = value.get("framework")
    if framework is not None and (not isinstance(framework, str) or not framework.strip()):
        raise RulePackError("targets.framework must be a string when provided")
    return RuleTarget(language=language, framework=framework)


def _parse_rule_pattern(value: Any) -> RulePattern:
    if not isinstance(value, dict):
        raise RulePackError("pattern entries must be tables")
    kind = _require_string(value.get("kind"), "patterns.kind")
    pattern_value = _require_string(value.get("value"), "patterns.value")
    description = value.get("description")
    if description is not None and not isinstance(description, str):
        raise RulePackError("patterns.description must be a string when provided")
    return RulePattern(kind=kind, value=pattern_value, description=description)


def _parse_rule(raw: dict[str, Any]) -> Rule:
    rule_id = _require_string(raw.get("id"), "id")
    name = _require_string(raw.get("name"), "name")
    description = _require_string(raw.get("description"), "description")
    category_raw = _require_string(raw.get("category"), "category")
    severity_raw = _require_string(raw.get("severity"), "severity")
    confidence_raw = _require_string(raw.get("confidence"), "confidence")
    strategy_raw = _require_string(raw.get("strategy"), "strategy")

    try:
        category = RuleCategory(category_raw)
    except ValueError as exc:
        raise RulePackError(f"unsupported rule category: {category_raw}") from exc

    try:
        severity = Severity(severity_raw)
    except ValueError as exc:
        raise RulePackError(f"unsupported severity: {severity_raw}") from exc

    try:
        confidence = Confidence(confidence_raw)
    except ValueError as exc:
        raise RulePackError(f"unsupported confidence: {confidence_raw}") from exc

    try:
        strategy = MatchStrategy(strategy_raw)
    except ValueError as exc:
        raise RulePackError(f"unsupported match strategy: {strategy_raw}") from exc

    targets = [_parse_rule_target(item) for item in _require_list(raw.get("targets", []), "targets")]
    patterns = [_parse_rule_pattern(item) for item in _require_list(raw.get("patterns", []), "patterns")]
    owasp = _require_list(raw.get("owasp", []), "owasp")
    cwe = _require_list(raw.get("cwe", []), "cwe")
    examples = _require_list(raw.get("examples", []), "examples")

    remediation = raw.get("remediation")
    if remediation is not None and not isinstance(remediation, str):
        raise RulePackError("remediation must be a string when provided")

    metadata = raw.get("metadata", {})
    if not isinstance(metadata, dict):
        raise RulePackError("metadata must be a table when provided")

    return Rule(
        id=rule_id,
        name=name,
        description=description,
        category=category,
        severity=severity,
        confidence=confidence,
        strategy=strategy,
        targets=targets,
        owasp=[str(item) for item in owasp],
        cwe=[str(item) for item in cwe],
        patterns=patterns,
        remediation=remediation,
        examples=[str(item) for item in examples],
        metadata=dict(metadata),
    )


def load_rule_pack(path: Path) -> RulePack:
    resolved = path.expanduser().resolve()
    if not resolved.exists():
        raise RulePackError(f"rule pack file does not exist: {resolved}")
    if resolved.is_dir():
        raise RulePackError(f"rule pack path must be a file: {resolved}")

    try:
        import tomllib
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise RulePackError("TOML parsing support is unavailable") from exc

    parsed = tomllib.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise RulePackError("rule pack root must be a table")

    name = _require_string(parsed.get("name"), "name")
    version = _require_string(parsed.get("version"), "version")
    metadata = parsed.get("metadata", {})
    if not isinstance(metadata, dict):
        raise RulePackError("metadata must be a table when provided")

    rules_raw = _require_list(parsed.get("rules", []), "rules")
    rules = []
    for item in rules_raw:
        if not isinstance(item, dict):
            raise RulePackError("rules entries must be tables")
        rules.append(_parse_rule(item))

    return RulePack(name=name, version=version, rules=rules, metadata=dict(metadata))

