from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Iterable, Sequence

from .detectors import (
    ANDROID_ACTIVITY_RULE,
    ANDROID_DANGEROUS_PERMISSION_RULE,
    ANDROID_RECEIVER_RULE,
    ANDROID_SHARED_PREFERENCES_RULE,
    AUTH_CHECK_RULE,
    DESERIALIZATION_RULE,
    FILE_ACCESS_RULE,
    ORM_RULE,
    OPEN_REDIRECT_RULE,
    PATH_TRAVERSAL_RULE,
    PROCESS_RULE,
    SCA_RULE,
    SECRET_RULE,
    SQLI_RULE,
    SSRF_RULE,
    TEMPLATE_RULE,
    XSS_RULE,
)
from .findings import Severity
from .rules import MatchStrategy, Rule, RuleCategory, RulePack, RulePattern, RuleTarget

BUILTIN_RULE_PACK_NAME = "builtin-detectors"
BUILTIN_RULE_PACK_VERSION = "0.1.0"

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _match_strategy_for_rule(rule_id: str) -> MatchStrategy:
    if rule_id == SECRET_RULE.rule_id:
        return MatchStrategy.PATTERN
    if rule_id == SCA_RULE.rule_id:
        return MatchStrategy.SCA
    if rule_id in {
        ANDROID_ACTIVITY_RULE.rule_id,
        ANDROID_DANGEROUS_PERMISSION_RULE.rule_id,
        ANDROID_RECEIVER_RULE.rule_id,
        ANDROID_SHARED_PREFERENCES_RULE.rule_id,
    }:
        return MatchStrategy.METADATA
    return MatchStrategy.TAINT


def _rule_from_template(template: Any) -> Rule:
    strategy = _match_strategy_for_rule(template.rule_id)
    metadata = {
        "source": "builtin-detector",
        "template_rule_id": template.rule_id,
        "tags": list(template.tags),
        "strategy": strategy.value,
    }
    return Rule(
        id=template.rule_id,
        name=template.title,
        description=template.message,
        category=template.category,
        severity=template.severity,
        confidence=template.confidence,
        strategy=strategy,
        targets=[RuleTarget(language="any")],
        owasp=list(template.owasp),
        cwe=list(template.cwe),
        patterns=[RulePattern(kind=strategy.value, value=template.rule_id, description=template.message)],
        remediation=template.remediation,
        examples=[],
        metadata=metadata,
    )


def build_builtin_rule_pack() -> RulePack:
    return RulePack(
        name=BUILTIN_RULE_PACK_NAME,
        version=BUILTIN_RULE_PACK_VERSION,
        rules=[
            _rule_from_template(template)
            for template in (
                SECRET_RULE,
                SQLI_RULE,
                DESERIALIZATION_RULE,
                ORM_RULE,
                XSS_RULE,
                SSRF_RULE,
                PATH_TRAVERSAL_RULE,
                FILE_ACCESS_RULE,
                PROCESS_RULE,
                ANDROID_ACTIVITY_RULE,
                ANDROID_RECEIVER_RULE,
                ANDROID_DANGEROUS_PERMISSION_RULE,
                ANDROID_SHARED_PREFERENCES_RULE,
                OPEN_REDIRECT_RULE,
                AUTH_CHECK_RULE,
                TEMPLATE_RULE,
                SCA_RULE,
            )
        ],
        metadata={
            "source": "builtin-detectors",
            "category": "browser",
            "description": "Detectors compiled into the MoSec CLI.",
        },
    )


def build_builtin_rule_packs() -> list[RulePack]:
    return [build_builtin_rule_pack()]


def rule_pack_labels(rule_packs: Sequence[RulePack]) -> list[str]:
    return [f"{pack.name}@{pack.version}" for pack in rule_packs]


def resolve_rule_pack_index(rule_packs: Sequence[RulePack], selection: str) -> int | None:
    normalized = selection.strip().lower()
    if not normalized:
        return None
    if normalized.isdigit():
        index = int(normalized) - 1
        if 0 <= index < len(rule_packs):
            return index
    for index, pack in enumerate(rule_packs):
        labels = {
            pack.name.lower(),
            pack.version.lower(),
            f"{pack.name}@{pack.version}".lower(),
        }
        if normalized in labels:
            return index
    return None


def _selected_rule_pack(rule_packs: Sequence[RulePack], selected_pack_index: int) -> RulePack | None:
    if not rule_packs:
        return None
    if selected_pack_index < 0 or selected_pack_index >= len(rule_packs):
        return rule_packs[0]
    return rule_packs[selected_pack_index]


def _selected_rule(rule_pack: RulePack | None, selected_rule_index: int) -> Rule | None:
    if rule_pack is None or not rule_pack.rules:
        return None
    if selected_rule_index < 0 or selected_rule_index >= len(rule_pack.rules):
        return rule_pack.rules[0]
    return rule_pack.rules[selected_rule_index]


def _pack_label(rule_pack: RulePack) -> str:
    return f"{rule_pack.name}@{rule_pack.version}"


def _rule_summary(rule: Rule) -> str:
    return f"{rule.id} | {rule.name} | {rule.severity.value} | {rule.strategy.value}"


def _rule_tags(rule: Rule) -> str:
    tags = rule.metadata.get("tags", [])
    if isinstance(tags, list) and tags:
        return ", ".join(str(tag) for tag in tags)
    return "n/a"


def _group_rules_by_category(rules: Iterable[Rule]) -> dict[RuleCategory, list[Rule]]:
    grouped: dict[RuleCategory, list[Rule]] = defaultdict(list)
    for rule in rules:
        grouped[rule.category].append(rule)
    for bucket in grouped.values():
        bucket.sort(key=lambda rule: (_SEVERITY_ORDER.get(rule.severity, 99), rule.id))
    return grouped


def rule_browser_lines(
    rule_packs: Sequence[RulePack],
    *,
    selected_pack_index: int = 0,
    selected_rule_index: int = 0,
) -> tuple[str, ...]:
    if not rule_packs:
        return (
            "Rules browser",
            "No rule packs are loaded yet.",
        )

    selected_pack = _selected_rule_pack(rule_packs, selected_pack_index)
    assert selected_pack is not None
    selected_rule = _selected_rule(selected_pack, selected_rule_index)
    total_rules = sum(len(pack.rules) for pack in rule_packs)

    lines = [
        "Rules browser",
        f"Loaded rule packs: {len(rule_packs)}",
        f"Loaded rules: {total_rules}",
        f"Selected pack: {_pack_label(selected_pack)}",
    ]

    if len(rule_packs) > 1:
        lines.append("Rule packs:")
        for index, pack in enumerate(rule_packs[:5], start=1):
            prefix = ">" if pack is selected_pack else " "
            lines.append(f"  {prefix} {index}. {_pack_label(pack)} ({len(pack.rules)} rules)")

    if selected_rule is not None:
        lines.extend(
            [
                "",
                "Selected rule",
                f"  {selected_rule.id}",
                f"  Name: {selected_rule.name}",
                f"  Category: {selected_rule.category.value}",
                f"  Severity: {selected_rule.severity.value}",
                f"  Confidence: {selected_rule.confidence.value}",
                f"  Strategy: {selected_rule.strategy.value}",
                f"  Remediation: {selected_rule.remediation or 'n/a'}",
                f"  OWASP: {', '.join(selected_rule.owasp) if selected_rule.owasp else 'n/a'}",
                f"  CWE: {', '.join(selected_rule.cwe) if selected_rule.cwe else 'n/a'}",
                f"  Tags: {_rule_tags(selected_rule)}",
            ]
        )

    grouped = _group_rules_by_category(selected_pack.rules)
    lines.append("")
    lines.append("Categories")
    for category in RuleCategory:
        bucket = grouped.get(category, [])
        if not bucket:
            continue
        lines.append(f"{category.value.replace('_', ' ').title()} ({len(bucket)})")
        for rule in bucket[:5]:
            lines.append(f"  - {_rule_summary(rule)}")
        if len(bucket) > 5:
            lines.append(f"  ... {len(bucket) - 5} more")

    return tuple(lines)


def render_rule_browser_lines(
    rule_packs: Sequence[RulePack],
    *,
    selected_pack_index: int = 0,
    selected_rule_index: int = 0,
) -> tuple[str, ...]:
    return rule_browser_lines(
        rule_packs,
        selected_pack_index=selected_pack_index,
        selected_rule_index=selected_rule_index,
    )


def rule_browser_payload(
    rule_packs: Sequence[RulePack],
    *,
    selected_pack_index: int = 0,
    selected_rule_index: int = 0,
) -> dict[str, Any]:
    selected_pack = _selected_rule_pack(rule_packs, selected_pack_index)
    selected_rule = _selected_rule(selected_pack, selected_rule_index)
    total_rules = sum(len(pack.rules) for pack in rule_packs)
    selected_pack_dict = None if selected_pack is None else selected_pack.to_dict()
    selected_rule_dict = None if selected_rule is None else selected_rule.to_dict()
    categories: list[dict[str, Any]] = []

    if selected_pack is not None:
        grouped = _group_rules_by_category(selected_pack.rules)
        for category in RuleCategory:
            bucket = grouped.get(category, [])
            if not bucket:
                continue
            categories.append(
                {
                    "category": category.value,
                    "count": len(bucket),
                    "rules": [rule.to_dict() for rule in bucket],
                }
            )

    return {
        "pack_count": len(rule_packs),
        "rule_count": total_rules,
        "selected_pack_index": selected_pack_index if rule_packs else None,
        "selected_rule_index": selected_rule_index if selected_rule is not None else None,
        "packs": [pack.to_dict() for pack in rule_packs],
        "selected_pack": selected_pack_dict,
        "selected_rule": selected_rule_dict,
        "categories": categories,
    }


def rule_browser_sarif(
    rule_packs: Sequence[RulePack],
    *,
    selected_pack_index: int = 0,
    selected_rule_index: int = 0,
) -> dict[str, Any]:
    selected_pack = _selected_rule_pack(rule_packs, selected_pack_index)
    selected_rule = _selected_rule(selected_pack, selected_rule_index)
    rules_by_id: dict[str, dict[str, object]] = {}
    all_rules = [rule for pack in rule_packs for rule in pack.rules]

    for rule in all_rules:
        rules_by_id.setdefault(
            rule.id,
            {
                "id": rule.id,
                "name": rule.name,
                "shortDescription": {"text": rule.description},
                "fullDescription": {"text": rule.description},
                "help": {"text": rule.remediation or rule.description},
                "properties": {
                    "category": rule.category.value,
                    "severity": rule.severity.value,
                    "confidence": rule.confidence.value,
                    "strategy": rule.strategy.value,
                    "owasp": list(rule.owasp),
                    "cwe": list(rule.cwe),
                    "tags": list(rule.metadata.get("tags", [])),
                },
            },
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mosec",
                        "version": BUILTIN_RULE_PACK_VERSION,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": [],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "view_id": "rules",
                            "view_title": "Rules",
                            "pack_count": len(rule_packs),
                            "rule_count": len(all_rules),
                            "selected_pack": None if selected_pack is None else selected_pack.to_dict(),
                            "selected_rule": None if selected_rule is None else selected_rule.to_dict(),
                            "rule_packs": [pack.to_dict() for pack in rule_packs],
                        },
                    }
                ],
            }
        ],
    }


def render_rule_browser_json(
    rule_packs: Sequence[RulePack],
    *,
    selected_pack_index: int = 0,
    selected_rule_index: int = 0,
) -> str:
    return json.dumps(
        rule_browser_payload(
            rule_packs,
            selected_pack_index=selected_pack_index,
            selected_rule_index=selected_rule_index,
        ),
        indent=2,
        sort_keys=True,
    )


def render_rule_browser_sarif(
    rule_packs: Sequence[RulePack],
    *,
    selected_pack_index: int = 0,
    selected_rule_index: int = 0,
) -> str:
    return json.dumps(
        rule_browser_sarif(
            rule_packs,
            selected_pack_index=selected_pack_index,
            selected_rule_index=selected_rule_index,
        ),
        indent=2,
        sort_keys=True,
    )
