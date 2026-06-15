from __future__ import annotations

from .findings import Finding, Severity


_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def parse_fail_on_threshold(value: str | None) -> Severity | None:
    if value is None:
        return None
    try:
        return Severity(value)
    except ValueError as exc:  # pragma: no cover - validated by CLI/config
        raise ValueError(f"unsupported fail-on severity: {value}") from exc


def findings_exceed_threshold(findings: list[Finding], threshold: str | None) -> bool:
    parsed_threshold = parse_fail_on_threshold(threshold)
    if parsed_threshold is None:
        return False

    threshold_level = _SEVERITY_ORDER[parsed_threshold]
    for finding in findings:
        if _SEVERITY_ORDER[finding.severity] >= threshold_level:
            return True
    return False


def policy_decision_for(findings: list[Finding], threshold: str | None) -> str:
    return "blocked" if findings_exceed_threshold(findings, threshold) else "allowed"


def resolve_policy_threshold(
    default_threshold: str | None,
    branch: str | None,
    branch_fail_on: dict[str, str],
    fail_on_explicit: bool = False,
) -> str | None:
    if not fail_on_explicit and branch is not None and branch in branch_fail_on:
        return branch_fail_on[branch]
    return default_threshold
