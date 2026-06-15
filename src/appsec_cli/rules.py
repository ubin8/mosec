from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from .findings import Confidence, Severity


class RuleCategory(StrEnum):
    SECRETS = "secrets"
    SCA = "sca"
    INJECTION = "injection"
    XSS = "xss"
    SSRF = "ssrf"
    ACCESS_CONTROL = "access_control"
    AUTHENTICATION = "authentication"
    DESERIALIZATION = "deserialization"
    TEMPLATE_INJECTION = "template_injection"
    PATH_TRAVERSAL = "path_traversal"
    FILE_ACCESS = "file_access"
    PROCESS_EXECUTION = "process_execution"
    OPEN_REDIRECT = "open_redirect"
    CRYPTO = "crypto"
    CONFIGURATION = "configuration"
    MOBILE = "mobile"
    CUSTOM = "custom"


class MatchStrategy(StrEnum):
    PATTERN = "pattern"
    TAINT = "taint"
    SCA = "sca"
    METADATA = "metadata"
    CUSTOM = "custom"


@dataclass(slots=True, frozen=True)
class RuleTarget:
    language: str
    framework: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "framework": self.framework,
        }


@dataclass(slots=True, frozen=True)
class RulePattern:
    kind: str
    value: str
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "description": self.description,
        }


@dataclass(slots=True, frozen=True)
class Rule:
    id: str
    name: str
    description: str
    category: RuleCategory
    severity: Severity
    confidence: Confidence
    strategy: MatchStrategy
    targets: list[RuleTarget] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    patterns: list[RulePattern] = field(default_factory=list)
    remediation: str | None = None
    examples: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "strategy": self.strategy.value,
            "targets": [target.to_dict() for target in self.targets],
            "owasp": list(self.owasp),
            "cwe": list(self.cwe),
            "patterns": [pattern.to_dict() for pattern in self.patterns],
            "remediation": self.remediation,
            "examples": list(self.examples),
            "metadata": dict(self.metadata),
        }


class RuleProvider(Protocol):
    def load_rules(self) -> list[Rule]:
        raise NotImplementedError


@dataclass(slots=True, frozen=True)
class RulePack:
    name: str
    version: str
    rules: list[Rule] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "rules": [rule.to_dict() for rule in self.rules],
            "metadata": dict(self.metadata),
        }
