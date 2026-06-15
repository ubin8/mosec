from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .findings import Severity


class DependencyScope(StrEnum):
    DIRECT = "direct"
    TRANSITIVE = "transitive"


@dataclass(slots=True, frozen=True)
class DependencyRecord:
    package: str
    version: str | None
    source_file: str
    scope: DependencyScope
    line: int | None = None
    ecosystem: str | None = None


@dataclass(slots=True, frozen=True)
class AdvisoryMatch:
    advisory_id: str
    package: str
    version: str | None
    title: str
    description: str
    severity: Severity
    cwe: list[str]
    source: str = "local-advisory"


class VulnerabilityBackend(Protocol):
    name: str

    def lookup(self, dependency: DependencyRecord) -> list[AdvisoryMatch]:
        raise NotImplementedError


class LocalAdvisoryBackend:
    name = "local-advisory"

    def __init__(self) -> None:
        self._database: dict[str, list[AdvisoryMatch]] = {
            "flask": [
                AdvisoryMatch(
                    advisory_id="ADV-PY-0001",
                    package="flask",
                    version=None,
                    title="Flask advisory",
                    description="Local advisory match for Flask packages.",
                    severity=Severity.HIGH,
                    cwe=["CWE-1104"],
                )
            ],
            "requests": [
                AdvisoryMatch(
                    advisory_id="ADV-PY-0002",
                    package="requests",
                    version=None,
                    title="Requests advisory",
                    description="Local advisory match for Requests packages.",
                    severity=Severity.MEDIUM,
                    cwe=["CWE-1104"],
                )
            ],
            "express": [
                AdvisoryMatch(
                    advisory_id="ADV-JS-0001",
                    package="express",
                    version=None,
                    title="Express advisory",
                    description="Local advisory match for Express packages.",
                    severity=Severity.HIGH,
                    cwe=["CWE-1104"],
                )
            ],
            "lodash": [
                AdvisoryMatch(
                    advisory_id="ADV-JS-0002",
                    package="lodash",
                    version=None,
                    title="Lodash advisory",
                    description="Local advisory match for Lodash packages.",
                    severity=Severity.MEDIUM,
                    cwe=["CWE-1104"],
                )
            ],
            "react": [
                AdvisoryMatch(
                    advisory_id="ADV-JS-0003",
                    package="react",
                    version=None,
                    title="React advisory",
                    description="Local advisory match for React packages.",
                    severity=Severity.MEDIUM,
                    cwe=["CWE-1104"],
                )
            ],
            "next": [
                AdvisoryMatch(
                    advisory_id="ADV-JS-0004",
                    package="next",
                    version=None,
                    title="Next.js advisory",
                    description="Local advisory match for Next.js packages.",
                    severity=Severity.HIGH,
                    cwe=["CWE-1104"],
                )
            ],
        }

    def lookup(self, dependency: DependencyRecord) -> list[AdvisoryMatch]:
        matches = self._database.get(dependency.package.lower(), [])
        return [
            AdvisoryMatch(
                advisory_id=match.advisory_id,
                package=match.package,
                version=dependency.version,
                title=match.title,
                description=match.description,
                severity=match.severity,
                cwe=list(match.cwe),
                source=match.source,
            )
            for match in matches
        ]
