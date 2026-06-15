from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any
import hashlib


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TriageStatus(StrEnum):
    UNTRIAGED = "untriaged"
    IN_REVIEW = "in_review"
    TRIAGED = "triaged"


class FindingStatus(StrEnum):
    NEW = "new"
    CONFIRMED = "confirmed"
    SUPPRESSED = "suppressed"
    BASELINED = "baselined"


@dataclass(slots=True, frozen=True)
class CodeLocation:
    path: Path
    start_line: int
    start_column: int = 1
    end_line: int | None = None
    end_column: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "start_line": self.start_line,
            "start_column": self.start_column,
            "end_line": self.end_line,
            "end_column": self.end_column,
        }


@dataclass(slots=True, frozen=True)
class Evidence:
    snippet: str
    start_line: int | None = None
    end_line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "snippet": self.snippet,
            "start_line": self.start_line,
            "end_line": self.end_line,
        }


@dataclass(slots=True, frozen=True)
class CodeSymbolReference:
    name: str
    kind: str | None = None
    qualified_name: str | None = None
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "qualified_name": self.qualified_name,
            "line": self.line,
        }


@dataclass(slots=True, frozen=True)
class Finding:
    id: str
    rule_id: str
    title: str
    message: str
    severity: Severity
    confidence: Confidence
    location: CodeLocation
    category: str
    language: str | None = None
    framework: str | None = None
    owasp: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    evidence: Evidence | None = None
    remediation: str | None = None
    status: FindingStatus = FindingStatus.NEW
    triage_status: TriageStatus = TriageStatus.UNTRIAGED
    triage_reason: str | None = None
    triage_note: str | None = None
    tags: list[str] = field(default_factory=list)
    symbols: list[CodeSymbolReference] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "message": self.message,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "location": self.location.to_dict(),
            "category": self.category,
            "language": self.language,
            "framework": self.framework,
            "owasp": list(self.owasp),
            "cwe": list(self.cwe),
            "evidence": None if self.evidence is None else self.evidence.to_dict(),
            "remediation": self.remediation,
            "status": self.status.value,
            "triage_status": self.triage_status.value,
            "triage_reason": self.triage_reason,
            "triage_note": self.triage_note,
            "tags": list(self.tags),
            "symbols": [symbol.to_dict() for symbol in self.symbols],
            "metadata": dict(self.metadata),
        }

    def to_summary(self) -> str:
        return (
            f"{self.severity.value.upper()} {self.title} "
            f"({self.rule_id}) at {self.location.path}:{self.location.start_line}"
        )

    def fingerprint(self) -> str:
        relative_path = str(self.metadata.get("relative_path", self.location.path.as_posix()))
        components = [
            self.rule_id,
            relative_path,
            str(self.location.start_line),
            self.evidence.snippet if self.evidence is not None else "",
        ]
        digest = hashlib.sha256("::".join(components).encode("utf-8")).hexdigest()
        return digest


@dataclass(slots=True, frozen=True)
class FindingBatch:
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> list[dict[str, Any]]:
        return [finding.to_dict() for finding in self.findings]
