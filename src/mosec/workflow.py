from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from .audit import AuditEntry
from .findings import Finding, FindingStatus


def _normalize_path(path: str | Path) -> str:
    normalized = Path(path).as_posix().lstrip("./")
    return normalized


def _parse_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


def _require_non_empty_string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"field '{field_name}' must be a non-empty string")
    return value.strip()


def _require_timestamp_string(value: object, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"field '{field_name}' must be a non-empty string")
    normalized = value.strip()
    parsed = _parse_timestamp(normalized)
    if parsed is None:
        raise ValueError(f"field '{field_name}' must be a valid RFC 3339 timestamp")
    return normalized


class SuppressionReviewStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ManualOverrideDecision(StrEnum):
    ACTIVE = "active"
    SUPPRESSED = "suppressed"


@dataclass(slots=True, frozen=True)
class BaselineEntry:
    rule_id: str
    path: str
    start_line: int
    fingerprint: str | None = None
    reason: str | None = None
    created_at: str | None = None

    def matches(self, finding: Finding) -> bool:
        if finding.rule_id != self.rule_id:
            return False
        finding_path = _normalize_path(finding.metadata.get("relative_path", finding.location.path))
        target_path = _normalize_path(self.path)
        if not finding_path.endswith(target_path) and finding_path != target_path:
            return False
        if finding.location.start_line != self.start_line:
            return False
        if self.fingerprint is None:
            return True
        if len(self.fingerprint) == 64 and all(ch in "0123456789abcdef" for ch in self.fingerprint.lower()):
            return self.fingerprint == finding.fingerprint()
        return True


@dataclass(slots=True, frozen=True)
class SuppressionTarget:
    rule_id: str
    path: str
    start_line: int

    def matches(self, finding: Finding) -> bool:
        return (
            finding.rule_id == self.rule_id
            and _normalize_path(finding.metadata.get("relative_path", finding.location.path)).endswith(
                _normalize_path(self.path)
            )
            and finding.location.start_line == self.start_line
        )


@dataclass(slots=True, frozen=True)
class Suppression:
    target: SuppressionTarget
    reason: str
    author: str | None = None
    created_at: str | None = None
    expires_at: str | None = None
    scope: str | None = None
    review_status: SuppressionReviewStatus = SuppressionReviewStatus.APPROVED
    reviewed_by: str | None = None
    reviewed_at: str | None = None
    review_note: str | None = None

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        expires_at = _parse_timestamp(self.expires_at)
        if expires_at is None:
            return False
        return expires_at < datetime.now(tz=expires_at.tzinfo)

    def expires_at_datetime(self) -> datetime | None:
        return _parse_timestamp(self.expires_at)

    def is_review_approved(self) -> bool:
        return self.review_status == SuppressionReviewStatus.APPROVED

    def matches(self, finding: Finding) -> bool:
        if self.is_expired() or not self.is_review_approved():
            return False
        return self.target.matches(finding)


@dataclass(slots=True, frozen=True)
class ManualOverrideTarget:
    rule_id: str
    path: str
    start_line: int

    def matches(self, finding: Finding) -> bool:
        return (
            finding.rule_id == self.rule_id
            and _normalize_path(finding.metadata.get("relative_path", finding.location.path)).endswith(
                _normalize_path(self.path)
            )
            and finding.location.start_line == self.start_line
        )


@dataclass(slots=True, frozen=True)
class ManualOverride:
    target: ManualOverrideTarget
    decision: ManualOverrideDecision
    reason: str
    author: str | None = None
    created_at: str | None = None
    expires_at: str | None = None
    scope: str | None = None

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        expires_at = _parse_timestamp(self.expires_at)
        if expires_at is None:
            return False
        return expires_at < datetime.now(tz=expires_at.tzinfo)

    def matches(self, finding: Finding) -> bool:
        if self.is_expired():
            return False
        return self.target.matches(finding)


@dataclass(slots=True)
class FilterResult:
    active_findings: list[Finding] = field(default_factory=list)
    baselined_findings: list[Finding] = field(default_factory=list)
    suppressed_findings: list[Finding] = field(default_factory=list)
    audit_entries: list[AuditEntry] = field(default_factory=list)


def load_baseline_file(path: Path | None) -> list[BaselineEntry]:
    if path is None:
        return []
    resolved = path.expanduser().resolve()
    if not resolved.exists():
        raise ValueError(f"baseline file does not exist: {resolved}")

    import json

    payload = json.loads(resolved.read_text(encoding="utf-8"))
    entries_raw = payload.get("entries", [])
    if not isinstance(entries_raw, list):
        raise ValueError("baseline entries must be a list")

    entries: list[BaselineEntry] = []
    for item in entries_raw:
        if not isinstance(item, dict):
            raise ValueError("baseline entries must be objects")
        entries.append(
            BaselineEntry(
                rule_id=str(item["rule_id"]),
                path=str(item["path"]),
                start_line=int(item["start_line"]),
                fingerprint=item.get("fingerprint"),
                reason=item.get("reason"),
                created_at=item.get("created_at"),
            )
        )
    return entries


def load_suppressions_file(path: Path | None) -> list[Suppression]:
    if path is None:
        return []
    resolved = path.expanduser().resolve()
    if not resolved.exists():
        raise ValueError(f"suppressions file does not exist: {resolved}")

    import json

    payload = json.loads(resolved.read_text(encoding="utf-8"))
    suppressions_raw = payload.get("suppressions", [])
    if not isinstance(suppressions_raw, list):
        raise ValueError("suppressions must be a list")

    suppressions: list[Suppression] = []
    for item in suppressions_raw:
        if not isinstance(item, dict):
            raise ValueError("suppression entries must be objects")
        target = item.get("target")
        if not isinstance(target, dict):
            raise ValueError("suppression target must be an object")
        review_status_value = item.get("review_status", SuppressionReviewStatus.APPROVED.value)
        try:
            review_status = SuppressionReviewStatus(review_status_value)
        except ValueError as exc:
            raise ValueError("field 'review_status' must be one of: pending, approved, rejected") from exc
        suppressions.append(
            Suppression(
                target=SuppressionTarget(
                    rule_id=str(target["rule_id"]),
                    path=str(target["path"]),
                    start_line=int(target["start_line"]),
                ),
                reason=_require_non_empty_string(item.get("reason"), "reason"),
                author=item.get("author"),
                created_at=item.get("created_at"),
                expires_at=_require_timestamp_string(item.get("expires_at"), "expires_at"),
                scope=item.get("scope"),
                review_status=review_status,
                reviewed_by=item.get("reviewed_by"),
                reviewed_at=_require_timestamp_string(item.get("reviewed_at"), "reviewed_at"),
                review_note=item.get("review_note"),
            )
        )
    return suppressions


def load_manual_overrides_file(path: Path | None) -> list[ManualOverride]:
    if path is None:
        return []
    resolved = path.expanduser().resolve()
    if not resolved.exists():
        raise ValueError(f"manual override file does not exist: {resolved}")

    import json

    payload = json.loads(resolved.read_text(encoding="utf-8"))
    overrides_raw = payload.get("overrides", [])
    if not isinstance(overrides_raw, list):
        raise ValueError("overrides must be a list")

    overrides: list[ManualOverride] = []
    for item in overrides_raw:
        if not isinstance(item, dict):
            raise ValueError("override entries must be objects")
        target = item.get("target")
        if not isinstance(target, dict):
            raise ValueError("override target must be an object")
        decision_value = item.get("decision")
        try:
            decision = ManualOverrideDecision(decision_value)
        except ValueError as exc:
            raise ValueError("field 'decision' must be one of: active, suppressed") from exc
        overrides.append(
            ManualOverride(
                target=ManualOverrideTarget(
                    rule_id=str(target["rule_id"]),
                    path=str(target["path"]),
                    start_line=int(target["start_line"]),
                ),
                decision=decision,
                reason=_require_non_empty_string(item.get("reason"), "reason"),
                author=item.get("author"),
                created_at=item.get("created_at"),
                expires_at=_require_timestamp_string(item.get("expires_at"), "expires_at"),
                scope=item.get("scope"),
            )
        )
    return overrides


def apply_baseline_and_suppressions(
    findings: list[Finding],
    baseline_entries: list[BaselineEntry] | None = None,
    suppressions: list[Suppression] | None = None,
    manual_overrides: list[ManualOverride] | None = None,
) -> FilterResult:
    baseline_entries = baseline_entries or []
    suppressions = suppressions or []
    manual_overrides = manual_overrides or []

    result = FilterResult()
    for finding in findings:
        matched_override = next((item for item in manual_overrides if item.matches(finding)), None)
        if matched_override is not None:
            if matched_override.decision == ManualOverrideDecision.ACTIVE:
                active = _clone_finding(
                    finding,
                    FindingStatus.NEW,
                    {
                        "manual_override_reason": matched_override.reason,
                        "manual_override_decision": matched_override.decision.value,
                    },
                )
                result.active_findings.append(active)
            else:
                suppressed = _clone_finding(
                    finding,
                    FindingStatus.SUPPRESSED,
                    {
                        "manual_override_reason": matched_override.reason,
                        "manual_override_decision": matched_override.decision.value,
                    },
                )
                result.suppressed_findings.append(suppressed)
            result.audit_entries.append(
                AuditEntry(
                    action="manual_override",
                    subject_type="finding",
                    subject_id=finding.id,
                    decision=matched_override.decision.value,
                    reason=matched_override.reason,
                    metadata={
                        "rule_id": finding.rule_id,
                        "path": str(finding.location.path),
                        "start_line": finding.location.start_line,
                        "scope": matched_override.scope,
                        "author": matched_override.author,
                        "expires_at": matched_override.expires_at,
                    },
                )
            )
            continue

        matched_baseline = next((entry for entry in baseline_entries if entry.matches(finding)), None)
        if matched_baseline is not None:
            baselined = _clone_finding(finding, FindingStatus.BASELINED, {"baseline_reason": matched_baseline.reason})
            result.baselined_findings.append(baselined)
            result.audit_entries.append(
                AuditEntry(
                    action="baseline",
                    subject_type="finding",
                    subject_id=finding.id,
                    decision="baselined",
                    reason=matched_baseline.reason,
                    metadata={
                        "rule_id": finding.rule_id,
                        "path": str(finding.location.path),
                        "start_line": finding.location.start_line,
                    },
                )
            )
            continue

        matched_suppression = next((item for item in suppressions if item.matches(finding)), None)
        if matched_suppression is not None:
            suppressed = _clone_finding(finding, FindingStatus.SUPPRESSED, {"suppression_reason": matched_suppression.reason})
            result.suppressed_findings.append(suppressed)
            result.audit_entries.append(
                AuditEntry(
                    action="suppression",
                    subject_type="finding",
                    subject_id=finding.id,
                    decision="suppressed",
                    reason=matched_suppression.reason,
                    metadata={
                        "rule_id": finding.rule_id,
                        "path": str(finding.location.path),
                        "start_line": finding.location.start_line,
                        "review_status": matched_suppression.review_status.value,
                        "reviewed_by": matched_suppression.reviewed_by,
                        "reviewed_at": matched_suppression.reviewed_at,
                    },
                )
            )
            continue

        result.active_findings.append(finding)

    return result


def _clone_finding(finding: Finding, status: FindingStatus, extra_metadata: dict[str, Any]) -> Finding:
    metadata = dict(finding.metadata)
    metadata.update(extra_metadata)
    return Finding(
        id=finding.id,
        rule_id=finding.rule_id,
        title=finding.title,
        message=finding.message,
        severity=finding.severity,
        confidence=finding.confidence,
        location=finding.location,
        category=finding.category,
        language=finding.language,
        framework=finding.framework,
        owasp=list(finding.owasp),
        cwe=list(finding.cwe),
        evidence=finding.evidence,
        remediation=finding.remediation,
        status=status,
        triage_status=finding.triage_status,
        triage_reason=finding.triage_reason,
        triage_note=finding.triage_note,
        tags=list(finding.tags),
        metadata=metadata,
    )
