from __future__ import annotations

from dataclasses import dataclass

from .commands import PromptSpec, normalize_command_text


@dataclass
class SessionState:
    workspace: str = "."
    scan_mode: str = "deep"
    output_format: str = "text"
    status_text: str = "Ready"
    status_kind: str = "info"
    last_scan_target: str | None = None
    last_scan_mode: str | None = None
    last_scan_format: str | None = None
    last_command: str | None = None

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
