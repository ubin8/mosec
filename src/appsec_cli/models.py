from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .audit import AuditEntry
from .detection import FileClassification
from .findings import Finding, Severity
from .parsing import ParsedDocument
from .rules import RulePack


@dataclass(slots=True)
class ScanStats:
    files_seen: int = 0
    files_selected: int = 0
    findings: int = 0
    baselined_findings: int = 0
    suppressed_findings: int = 0


@dataclass(slots=True)
class ScanResult:
    root: Path
    started_at: str | None = None
    finished_at: str | None = None
    tool_version: str | None = None
    policy_branch: str | None = None
    stats: ScanStats = field(default_factory=ScanStats)
    notes: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    files: list[FileClassification] = field(default_factory=list)
    parsed_documents: list[ParsedDocument] = field(default_factory=list)
    baseline_findings: list[Finding] = field(default_factory=list)
    suppressed_findings: list[Finding] = field(default_factory=list)
    audit_log: list[AuditEntry] = field(default_factory=list)
    rule_packs: list[RulePack] = field(default_factory=list)
    policy_threshold: str | None = None
    policy_effective_threshold: str | None = None
    policy_decision: str | None = None

    _severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    _reachability_order = {
        "reachable": 0,
        "unknown": 1,
        "unreachable": 2,
    }

    def __post_init__(self) -> None:
        self.finalize()

    def finalize(self) -> None:
        self.findings.sort(key=self._finding_sort_key)
        self.baseline_findings.sort(key=self._finding_sort_key)
        self.suppressed_findings.sort(key=self._finding_sort_key)
        self.stats.findings = len(self.findings)
        self.stats.baselined_findings = len(self.baseline_findings)
        self.stats.suppressed_findings = len(self.suppressed_findings)

    def _finding_sort_key(self, finding: Finding) -> tuple[int, str, int, str]:
        reachability = str(finding.metadata.get("taint_reachability", "reachable")).lower()
        return (
            self._severity_order[finding.severity],
            self._reachability_order.get(reachability, 1),
            str(finding.location.path),
            finding.location.start_line,
            finding.rule_id,
        )

    def to_text(self) -> str:
        finding_lines = "\n".join(f"- {finding.to_summary()}" for finding in self.findings)
        finding_block = finding_lines if finding_lines else "- no active findings"
        status_lines = []
        if self.stats.baselined_findings:
            status_lines.append(f"- baselined: {self.stats.baselined_findings}")
        if self.stats.suppressed_findings:
            status_lines.append(f"- suppressed: {self.stats.suppressed_findings}")
        status_section = ""
        if status_lines:
            status_section = "filtered:\n" + "\n".join(status_lines) + "\n"
        rule_pack_lines = []
        if self.rule_packs:
            rule_pack_lines = [f"- {pack.name}@{pack.version}" for pack in self.rule_packs]
        rule_pack_section = ""
        if rule_pack_lines:
            rule_pack_section = "rule packs:\n" + "\n".join(rule_pack_lines) + "\n"
        audit_lines = []
        if self.audit_log:
            audit_lines = [f"- {entry.to_summary()}" for entry in self.audit_log]
        audit_section = ""
        if audit_lines:
            audit_section = "audit log:\n" + "\n".join(audit_lines) + "\n"
        policy_lines = []
        if self.policy_threshold is not None:
            policy_lines.append(f"- threshold: {self.policy_threshold}")
        if self.policy_effective_threshold is not None:
            policy_lines.append(f"- effective threshold: {self.policy_effective_threshold}")
        if self.policy_decision is not None:
            policy_lines.append(f"- decision: {self.policy_decision}")
        policy_section = ""
        if policy_lines:
            policy_section = "policy:\n" + "\n".join(policy_lines) + "\n"
        notes_block = "\n".join(f"- {note}" for note in self.notes)
        notes_section = f"notes:\n{notes_block}\n" if notes_block else ""
        lines = [f"scan root: {self.root}"]
        if self.started_at is not None:
            lines.append(f"started at: {self.started_at}")
        if self.finished_at is not None:
            lines.append(f"finished at: {self.finished_at}")
        if self.tool_version is not None:
            lines.append(f"tool version: {self.tool_version}")
        if self.policy_branch is not None:
            lines.append(f"policy branch: {self.policy_branch}")
        lines.append(f"files seen: {self.stats.files_seen}")
        lines.append(f"files selected: {self.stats.files_selected}")
        lines.append(f"findings: {self.stats.findings}")
        if status_section:
            lines.append(status_section.rstrip("\n"))
        if rule_pack_section:
            lines.append(rule_pack_section.rstrip("\n"))
        if audit_section:
            lines.append(audit_section.rstrip("\n"))
        if policy_section:
            lines.append(policy_section.rstrip("\n"))
        if notes_section:
            lines.append(notes_section.rstrip("\n"))
        lines.append(finding_block)
        return "\n".join(lines)

    def to_json(self) -> str:
        import json

        return json.dumps(
            {
                "root": str(self.root),
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "tool_version": self.tool_version,
                "policy_branch": self.policy_branch,
                "stats": {
                    "files_seen": self.stats.files_seen,
                    "files_selected": self.stats.files_selected,
                    "findings": self.stats.findings,
                    "baselined_findings": self.stats.baselined_findings,
                    "suppressed_findings": self.stats.suppressed_findings,
                },
                "notes": self.notes,
                "findings": [finding.to_dict() for finding in self.findings],
                "baselined_findings": [finding.to_dict() for finding in self.baseline_findings],
                "suppressed_findings": [finding.to_dict() for finding in self.suppressed_findings],
                "audit_log": [entry.to_dict() for entry in self.audit_log],
                "rule_packs": [pack.to_dict() for pack in self.rule_packs],
                "policy_threshold": self.policy_threshold,
                "policy_effective_threshold": self.policy_effective_threshold,
                "policy_decision": self.policy_decision,
                "files": [file.to_dict() for file in self.files],
                "parsed_documents": [document.to_dict() for document in self.parsed_documents],
            },
            indent=2,
            sort_keys=True,
        )
