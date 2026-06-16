from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

from .commands import PromptSpec, normalize_command_text
from .findings import TriageStatus
from .rule_browser import build_builtin_rule_packs
from .rules import RulePack

if TYPE_CHECKING:
    from .findings import Finding
    from .rules import Rule


@dataclass
class SessionState:
    workspace: str = "."
    scan_mode: str = "deep"
    output_format: str = "text"
    current_view: str = "home"
    status_text: str = "Ready"
    status_kind: str = "info"
    findings: list["Finding"] = None  # type: ignore[assignment]
    baseline_findings: list["Finding"] = field(default_factory=list)
    suppressed_findings: list["Finding"] = field(default_factory=list)
    rule_packs: list[RulePack] = field(default_factory=build_builtin_rule_packs)
    selected_rule_pack_index: int = 0
    selected_rule_index: int = 0
    selected_finding_index: int = 0
    selected_suppressed_finding_index: int = 0
    findings_search_query: str | None = None
    findings_severity_filters: list[str] = field(default_factory=list)
    last_scan_target: str | None = None
    last_scan_mode: str | None = None
    last_scan_format: str | None = None
    last_command: str | None = None

    def __post_init__(self) -> None:
        if self.findings is None:
            self.findings = []
        if not self.rule_packs:
            self.rule_packs = build_builtin_rule_packs()
        if self.selected_rule_pack_index < 0 or self.selected_rule_pack_index >= len(self.rule_packs):
            self.selected_rule_pack_index = 0
        if self.selected_rule_index < 0:
            self.selected_rule_index = 0

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
        self.current_view = "scan"
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

    def store_scan_results(
        self,
        findings: list["Finding"],
        *,
        baseline_findings: list["Finding"] | None = None,
        suppressed_findings: list["Finding"] | None = None,
    ) -> None:
        self.store_findings(findings)
        if baseline_findings is not None:
            self.baseline_findings = list(baseline_findings)
        if suppressed_findings is not None:
            self.suppressed_findings = list(suppressed_findings)
            self.selected_suppressed_finding_index = 0

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

    def selected_baseline_finding(self) -> "Finding | None":
        return self.selected_finding_from(self.baseline_findings)

    def selected_suppressed_finding(self) -> "Finding | None":
        if not self.suppressed_findings:
            return None
        if (
            self.selected_suppressed_finding_index < 0
            or self.selected_suppressed_finding_index >= len(self.suppressed_findings)
        ):
            return self.suppressed_findings[0]
        return self.suppressed_findings[self.selected_suppressed_finding_index]

    def selected_rule_pack(self) -> RulePack | None:
        if not self.rule_packs:
            return None
        if self.selected_rule_pack_index < 0 or self.selected_rule_pack_index >= len(self.rule_packs):
            return self.rule_packs[0]
        return self.rule_packs[self.selected_rule_pack_index]

    def selected_rule(self) -> "Rule | None":
        pack = self.selected_rule_pack()
        if pack is None or not pack.rules:
            return None
        if self.selected_rule_index < 0 or self.selected_rule_index >= len(pack.rules):
            return pack.rules[0]
        return pack.rules[self.selected_rule_index]

    def set_current_view(self, view: str) -> None:
        normalized = view.strip().lower()
        if normalized:
            self.current_view = normalized

    def current_view_title(self) -> str:
        titles = {
            "home": "Home",
            "scan": "Scan",
            "findings": "Findings",
            "findings-baselined": "Baselined findings",
            "suppression-review": "Suppression review",
            "finding-detail": "Finding detail",
            "rules": "Rules",
            "rule-detail": "Rule detail",
            "workspace": "Workspace",
            "history": "History",
            "reports": "Reports",
            "policy": "Policy",
            "mobile": "Mobile",
            "settings": "Settings",
        }
        return titles.get(self.current_view, self.current_view.replace("-", " ").title())

    def current_view_rules(self) -> list["Rule"]:
        if self.current_view not in {"rules", "rule-detail"}:
            return []
        pack = self.selected_rule_pack()
        return [] if pack is None else list(pack.rules)

    def current_view_selected_rule(self) -> "Rule | None":
        if self.current_view not in {"rules", "rule-detail"}:
            return None
        return self.selected_rule()

    def current_view_findings(self) -> list["Finding"]:
        if self.current_view == "findings-baselined":
            return list(self.baseline_findings)
        if self.current_view == "suppression-review":
            return list(self.suppressed_findings)
        if self.current_view == "finding-detail":
            selected = self.selected_finding()
            return [] if selected is None else [selected]
        if self.current_view == "findings":
            return list(self.filtered_findings())
        if self.current_view == "scan":
            return list(self.findings)
        return []

    def current_view_selected_finding(self) -> "Finding | None":
        if self.current_view == "findings-baselined":
            return self.selected_baseline_finding()
        if self.current_view == "suppression-review":
            return self.selected_suppressed_finding()
        if self.current_view in {"findings", "scan", "finding-detail"}:
            return self.selected_finding()
        return None

    def update_selected_finding_triage(
        self,
        triage_status: TriageStatus,
        *,
        reason: str | None = None,
        note: str | None = None,
    ) -> "Finding | None":
        selected = self.selected_finding()
        if selected is None:
            return None

        updated = replace(
            selected,
            triage_status=triage_status,
            triage_reason=reason.strip() if reason is not None and reason.strip() else None,
            triage_note=note.strip() if note is not None and note.strip() else None,
        )
        try:
            selected_index = self.findings.index(selected)
        except ValueError:
            return None
        self.findings[selected_index] = updated
        return updated

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
            f"Current view: {self.current_view}",
            f"Loaded findings: {len(self.findings)}",
            f"Baselined findings: {len(self.baseline_findings)}",
            f"Suppressed findings: {len(self.suppressed_findings)}",
            f"Loaded rule packs: {len(self.rule_packs)}",
            f"Loaded rules: {sum(len(pack.rules) for pack in self.rule_packs)}",
            f"Findings search: {self.findings_search_query or 'none'}",
            f"Findings severity filters: {', '.join(self.findings_severity_filters) if self.findings_severity_filters else 'none'}",
        ]
        selected_rule_pack = self.selected_rule_pack()
        if selected_rule_pack is None:
            lines.append("Selected rule pack: none")
        else:
            lines.append(f"Selected rule pack: {selected_rule_pack.name}@{selected_rule_pack.version}")
        selected_rule = self.selected_rule()
        if selected_rule is not None:
            lines.append(f"Selected rule: {selected_rule.id} - {selected_rule.name}")
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
