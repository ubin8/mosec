from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .commands import PromptSpec, normalize_command_text

if TYPE_CHECKING:
    from .findings import Finding


@dataclass
class SessionState:
    workspace: str = "."
    scan_mode: str = "deep"
    output_format: str = "text"
    status_text: str = "Ready"
    status_kind: str = "info"
    findings: list["Finding"] = None  # type: ignore[assignment]
    selected_finding_index: int = 0
    findings_search_query: str | None = None
    findings_severity_filters: list[str] = field(default_factory=list)
    last_scan_target: str | None = None
    last_scan_mode: str | None = None
    last_scan_format: str | None = None
    last_command: str | None = None

    def __post_init__(self) -> None:
        if self.findings is None:
            self.findings = []

    def remember_command(self, command: str) -> None:
        normalized = normalize_command_text(command)
        if normalized is not None:
            self.last_command = normalized
        elif command.strip():
            self.last_command = command.strip()

    def record_scan(self, target: str, mode: str, output_format: str) -> None:
        self.workspace = target or self.workspace
        self.scan_mode = mode or self.scan_mode
        self.output_format = output_format or self.output_format
        self.last_scan_target = self.workspace
        self.last_scan_mode = self.scan_mode
        self.last_scan_format = self.output_format
        self.set_status(f"Scan prepared for {self.workspace}", kind="success")

    def repeat_last_scan(self) -> bool:
        if self.last_scan_target is None:
            return False
        self.workspace = self.last_scan_target
        self.scan_mode = self.last_scan_mode or self.scan_mode
        self.output_format = self.last_scan_format or self.output_format
        self.set_status(f"Repeated scan prepared for {self.workspace}", kind="success")
        return True

    def compare_current_to_last_scan(self) -> tuple[str, ...] | None:
        if self.last_scan_target is None:
            return None
        target_changed = self.workspace != self.last_scan_target
        mode_changed = self.scan_mode != (self.last_scan_mode or self.scan_mode)
        format_changed = self.output_format != (self.last_scan_format or self.output_format)
        return (
            "Scan comparison",
            f"Current target: {self.workspace}",
            f"Last target: {self.last_scan_target}",
            f"Target changed: {'yes' if target_changed else 'no'}",
            f"Current mode: {self.scan_mode}",
            f"Last mode: {self.last_scan_mode or self.scan_mode}",
            f"Mode changed: {'yes' if mode_changed else 'no'}",
            f"Current format: {self.output_format}",
            f"Last format: {self.last_scan_format or self.output_format}",
            f"Format changed: {'yes' if format_changed else 'no'}",
        )

    def store_findings(self, findings: list["Finding"]) -> None:
        self.findings = list(findings)
        self.selected_finding_index = 0
        if self.findings:
            self.set_status(f"Loaded {len(self.findings)} findings.", kind="success")

    def set_findings_search_query(self, query: str | None) -> None:
        value = query.strip() if query is not None else ""
        self.findings_search_query = value or None
        self.selected_finding_index = 0

    def set_findings_severity_filters(self, severities: list[str]) -> None:
        normalized = [severity.strip().lower() for severity in severities if severity.strip()]
        self.findings_severity_filters = normalized
        self.selected_finding_index = 0

    def clear_findings_filters(self) -> None:
        self.findings_search_query = None
        self.findings_severity_filters = []
        self.selected_finding_index = 0

    def filtered_findings(self) -> list["Finding"]:
        findings = list(self.findings)
        if self.findings_search_query is not None:
            query = self.findings_search_query.lower()
            findings = [
                finding
                for finding in findings
                if query in finding.title.lower()
                or query in finding.message.lower()
                or query in finding.rule_id.lower()
                or query in str(finding.location.path).lower()
                or query in finding.severity.value.lower()
            ]
        if self.findings_severity_filters:
            allowed = set(self.findings_severity_filters)
            findings = [finding for finding in findings if finding.severity.value in allowed]
        return findings

    def findings_filter_summary(self) -> tuple[str, ...]:
        search = self.findings_search_query or "none"
        severities = ", ".join(self.findings_severity_filters) if self.findings_severity_filters else "all"
        return (
            f"Search query: {search}",
            f"Severity filters: {severities}",
            f"Visible findings: {len(self.filtered_findings())} / {len(self.findings)}",
        )

    def selected_finding(self) -> "Finding | None":
        findings = self.filtered_findings()
        if not findings:
            return None
        if self.selected_finding_index < 0 or self.selected_finding_index >= len(findings):
            return findings[0]
        return findings[self.selected_finding_index]

    def selected_finding_from(self, findings: list["Finding"]) -> "Finding | None":
        if not findings:
            return None
        if self.selected_finding_index < 0 or self.selected_finding_index >= len(findings):
            return findings[0]
        return findings[self.selected_finding_index]

    def set_status(self, text: str, *, kind: str = "info") -> None:
        self.status_text = text.strip() or self.status_text
        self.status_kind = kind.strip().lower() or self.status_kind

    def scan_prompt_specs(self) -> tuple[PromptSpec, ...]:
        return (
            PromptSpec(key="target", question="Target path", default=self.workspace),
            PromptSpec(
                key="mode",
                question="Scan mode",
                default=self.scan_mode,
                choices=("quick", "deep", "web", "mobile", "secrets", "sca", "policy"),
            ),
            PromptSpec(
                key="format",
                question="Output format",
                default=self.output_format,
                choices=("text", "json", "sarif"),
            ),
        )

    def summary_lines(self) -> tuple[str, ...]:
        lines = [
            "Session state",
            f"Status [{self.status_kind.upper()}]: {self.status_text}",
            f"Workspace: {self.workspace}",
            f"Current mode: {self.scan_mode}",
            f"Output format: {self.output_format}",
            f"Loaded findings: {len(self.findings)}",
            f"Findings search: {self.findings_search_query or 'none'}",
            f"Findings severity filters: {', '.join(self.findings_severity_filters) if self.findings_severity_filters else 'none'}",
        ]
        if self.last_scan_target is None:
            lines.append("Last scan: none")
        else:
            lines.extend(
                [
                    f"Last scan target: {self.last_scan_target}",
                    f"Last scan mode: {self.last_scan_mode or self.scan_mode}",
                    f"Last scan format: {self.last_scan_format or self.output_format}",
                ]
            )
        if self.last_command is not None:
            lines.append(f"Last command: {self.last_command}")
        return tuple(lines)
