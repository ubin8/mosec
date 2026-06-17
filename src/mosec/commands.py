from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable, Sequence


@dataclass(frozen=True)
class PromptSpec:
    key: str
    question: str
    default: str | None = None
    choices: tuple[str, ...] = ()


@dataclass(frozen=True)
class CommandSpec:
    name: str
    summary: str
    description: str
    aliases: tuple[str, ...] = ()
    category: str = "General"
    implemented: bool = True


@dataclass(frozen=True)
class CommandOutcome:
    command: CommandSpec | None
    kind: str
    message_lines: tuple[str, ...] = ()
    prompt_steps: tuple[PromptSpec, ...] = ()
    confirmation: "ConfirmationSpec | None" = None
    should_exit: bool = False
    clear_screen: bool = False


@dataclass(frozen=True)
class ConfirmationSpec:
    question: str
    action: str
    destructive: bool = False


def normalize_command_text(text: str) -> str | None:
    candidate = text.strip()
    if not candidate:
        return None
    if any(character.isspace() for character in candidate):
        return None
    if not candidate.startswith("/"):
        return None
    return candidate.lower()


def _format_command_line(spec: CommandSpec) -> str:
    aliases = ", ".join(spec.aliases)
    suffix = f" ({aliases})" if aliases else ""
    return f"{spec.name:<16} {spec.summary}{suffix}"


class CommandRegistry:
    def __init__(self, commands: Iterable[CommandSpec]):
        self._commands = tuple(commands)
        self._lookup: dict[str, CommandSpec] = {}
        for command in self._commands:
            self._lookup[command.name] = command
            for alias in command.aliases:
                self._lookup[alias] = command

    @property
    def commands(self) -> tuple[CommandSpec, ...]:
        return self._commands

    def resolve(self, text: str) -> CommandSpec | None:
        normalized = normalize_command_text(text)
        if normalized is None:
            return None
        return self._lookup.get(normalized)

    def help_lines(self) -> tuple[str, ...]:
        grouped: dict[str, list[CommandSpec]] = defaultdict(list)
        for command in self._commands:
            grouped[command.category].append(command)

        lines: list[str] = [
            "MoSec commands",
            "",
            "Exact slash commands only. Type one command per line.",
            "",
        ]
        for category in sorted(grouped):
            lines.append(category)
            for command in grouped[category]:
                lines.append(f"  {_format_command_line(command)}")
            lines.append("")
        lines.extend(
            [
                "Use /help at any time to reopen this list.",
                "Use /exit to leave the TUI.",
            ]
        )
        return tuple(lines)

    def execute(self, text: str) -> CommandOutcome:
        normalized = normalize_command_text(text)
        if normalized is None:
            return CommandOutcome(
                command=None,
                kind="invalid",
                message_lines=(
                    "Commands must be exact slash commands.",
                    "Type /help to see the available actions.",
                ),
            )

        command = self._lookup.get(normalized)
        if command is None:
            return CommandOutcome(
                command=None,
                kind="unknown",
                message_lines=(
                    f"Unknown command: {normalized}",
                    "Type /help to see the available actions.",
                ),
            )

        if command.name == "/help":
            return CommandOutcome(command=command, kind="help", message_lines=self.help_lines())
        if command.name == "/exit":
            return CommandOutcome(
                command=command,
                kind="confirm",
                message_lines=("Confirmation required before exiting MoSec.",),
                confirmation=ConfirmationSpec(question="Exit MoSec", action="exit", destructive=True),
            )
        if command.name == "/clear":
            return CommandOutcome(
                command=command,
                kind="confirm",
                message_lines=("Confirmation required before clearing the terminal.",),
                confirmation=ConfirmationSpec(question="Clear the terminal surface", action="clear", destructive=True),
            )

        if command.name == "/scan":
            return CommandOutcome(
                command=command,
                kind="wizard",
                message_lines=(
                    "Guided scan wizard started.",
                    "MoSec will ask for target path, scan mode, and output format.",
                ),
                prompt_steps=(
                    PromptSpec(key="target", question="Target path", default="."),
                    PromptSpec(
                        key="mode",
                        question="Scan mode",
                        default="deep",
                        choices=("quick", "deep", "web", "mobile", "secrets", "sca", "policy"),
                    ),
                    PromptSpec(
                        key="format",
                        question="Output format",
                        default="text",
                        choices=("text", "json", "sarif"),
                    ),
                ),
            )

        if command.name.startswith("/scan"):
            return CommandOutcome(
                command=command,
                kind="scan",
                message_lines=(
                    f"Recognized {command.name}.",
                    "Guided scan workflows will be enabled in the next roadmap chunk.",
                ),
            )
        if command.name == "/findings-search":
            return CommandOutcome(
                command=command,
                kind="workspace",
                message_lines=("Search findings.",),
                prompt_steps=(PromptSpec(key="query", question="Search query"),),
            )
        if command.name == "/findings-baselined":
            return CommandOutcome(
                command=command,
                kind="workspace",
                message_lines=("Open baselined findings.",),
            )
        if command.name == "/suppression-review":
            return CommandOutcome(
                command=command,
                kind="workspace",
                message_lines=("Open suppression review.",),
            )
        if command.name == "/findings-filter-severity":
            return CommandOutcome(
                command=command,
                kind="workspace",
                message_lines=("Filter findings by severity.",),
                prompt_steps=(
                    PromptSpec(
                        key="severity",
                        question="Severity",
                        default="high",
                        choices=("critical", "high", "medium", "low", "info"),
                    ),
                ),
            )
        if command.name == "/findings-clear-filters":
            return CommandOutcome(
                command=command,
                kind="workspace",
                message_lines=("Findings filters cleared.",),
            )
        if command.name in {"/export-json", "/export-sarif"}:
            return CommandOutcome(
                command=command,
                kind="export",
                message_lines=(f"Exporting the current view as {command.name.removeprefix('/export-')}.",),
            )
        if command.name == "/triage-in-review":
            return CommandOutcome(
                command=command,
                kind="workspace",
                message_lines=("Mark the selected finding as in review.",),
                prompt_steps=(
                    PromptSpec(key="reason", question="Triage reason"),
                    PromptSpec(key="note", question="Triage note"),
                ),
            )
        if command.name == "/triage-triaged":
            return CommandOutcome(
                command=command,
                kind="workspace",
                message_lines=("Mark the selected finding as triaged.",),
                prompt_steps=(
                    PromptSpec(key="reason", question="Triage reason"),
                    PromptSpec(key="note", question="Triage note"),
                ),
            )
        if command.name == "/triage-untriaged":
            return CommandOutcome(
                command=command,
                kind="workspace",
                message_lines=("Reset the selected finding to untriaged.",),
            )
        if command.name == "/rules":
            return CommandOutcome(
                command=command,
                kind="workspace",
                message_lines=(
                    "Rules browser opened.",
                    "Browse builtin rule packs and inspect detector coverage.",
                ),
            )
        if command.name == "/rule-detail":
            return CommandOutcome(
                command=command,
                kind="workspace",
                message_lines=(
                    "Rule detail opened.",
                    "Inspect the currently selected rule in detail.",
                ),
            )
        if command.name == "/rule-pack-next":
            return CommandOutcome(
                command=command,
                kind="workspace",
                message_lines=("Select the next rule pack.",),
            )
        if command.name == "/rule-pack-prev":
            return CommandOutcome(
                command=command,
                kind="workspace",
                message_lines=("Select the previous rule pack.",),
            )
        if command.name == "/rule-pack-select":
            return CommandOutcome(
                command=command,
                kind="workspace",
                message_lines=("Select a rule pack.",),
                prompt_steps=(
                    PromptSpec(key="pack", question="Rule pack", default="1"),
                ),
            )
        if command.name == "/policy":
            return CommandOutcome(
                command=command,
                kind="workspace",
                message_lines=(
                    "Policy editor opened.",
                    "Inspect the active threshold, branch context, and overrides.",
                ),
            )
        if command.name == "/policy-threshold":
            return CommandOutcome(
                command=command,
                kind="workspace",
                message_lines=("Set the policy threshold.",),
                prompt_steps=(
                    PromptSpec(key="threshold", question="Policy threshold", default="none", choices=("none", "low", "medium", "high", "critical")),
                ),
            )
        if command.name == "/policy-branch":
            return CommandOutcome(
                command=command,
                kind="workspace",
                message_lines=("Review a specific branch policy state.",),
                prompt_steps=(
                    PromptSpec(key="branch", question="Branch name", default="main"),
                ),
            )
        if command.name == "/audit-trail":
            return CommandOutcome(
                command=command,
                kind="workspace",
                message_lines=(
                    "Audit trail opened.",
                    "Inspect recorded command, scan, policy, and review actions.",
                ),
            )
        if command.name == "/manual-overrides":
            return CommandOutcome(
                command=command,
                kind="workspace",
                message_lines=(
                    "Manual override management opened.",
                    "Inspect overrides that keep findings active or suppressed.",
                ),
            )
        if command.name in {"/findings", "/finding-detail", "/reports", "/mobile", "/workspace", "/history", "/settings"}:
            return CommandOutcome(
                command=command,
                kind="workspace",
                message_lines=(
                    f"Recognized {command.name}.",
                    "This workspace view will be filled in during the next roadmap chunks.",
                ),
            )
        if command.name in {"/back"}:
            return CommandOutcome(command=command, kind="navigation", message_lines=("Returning to the previous screen.",))

        return CommandOutcome(command=command, kind="noop")


@dataclass
class CommandHistory:
    limit: int = 50
    _entries: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self._entries is None:
            self._entries = []

    def add(self, command: str) -> None:
        normalized = normalize_command_text(command)
        if normalized is None:
            return
        self._entries.append(normalized)
        if len(self._entries) > self.limit:
            del self._entries[: len(self._entries) - self.limit]

    def recent(self) -> tuple[str, ...]:
        return tuple(reversed(self._entries))

    def previous(self) -> str | None:
        if len(self._entries) < 2:
            return None
        return self._entries[-2]


def build_default_command_registry() -> CommandRegistry:
    return CommandRegistry(
        (
            CommandSpec(
                name="/help",
                aliases=("/h", "/"),
                summary="Show the command list and shortcuts",
                description="Open the list of exact slash commands.",
                category="Navigation",
            ),
            CommandSpec(
                name="/scan",
                aliases=("/s",),
                summary="Open the guided scan wizard",
                description="Start a guided scan and collect the remaining context in prompts.",
                category="Scanning",
                implemented=True,
            ),
            CommandSpec(
                name="/scan-quick",
                aliases=("/quick-scan",),
                summary="Run a fast workspace scan",
                description="Quickly scan the current workspace with the most useful high-signal checks.",
                category="Scanning",
                implemented=False,
            ),
            CommandSpec(
                name="/scan-deep",
                aliases=("/deep-scan",),
                summary="Run a full analysis scan",
                description="Run the deeper analysis mode with the broader detector set.",
                category="Scanning",
                implemented=False,
            ),
            CommandSpec(
                name="/scan-web",
                aliases=("/web-scan",),
                summary="Run a web-focused scan",
                description="Focus the scan on web application risk patterns.",
                category="Scanning",
                implemented=False,
            ),
            CommandSpec(
                name="/scan-mobile",
                aliases=("/mobile-scan",),
                summary="Run a mobile-focused scan",
                description="Focus the scan on Android and iOS risk patterns.",
                category="Scanning",
                implemented=False,
            ),
            CommandSpec(
                name="/scan-secrets",
                aliases=("/secrets-scan",),
                summary="Run a secrets-only scan",
                description="Scan only for hardcoded credentials, tokens, and private key material.",
                category="Scanning",
                implemented=False,
            ),
            CommandSpec(
                name="/scan-sca",
                aliases=("/deps-scan", "/sca-scan"),
                summary="Run a dependency-only scan",
                description="Scan dependency manifests and lockfiles for vulnerable packages.",
                category="Scanning",
                implemented=False,
            ),
            CommandSpec(
                name="/scan-policy",
                aliases=("/policy-scan",),
                summary="Review policy and baseline state",
                description="Inspect baselines, suppressions, overrides, and policy thresholds.",
                category="Scanning",
                implemented=False,
            ),
            CommandSpec(
                name="/scan-repeat",
                aliases=("/repeat-last-scan",),
                summary="Repeat the last scan",
                description="Repeat the most recent scan settings for the current session.",
                category="Scanning",
                implemented=True,
            ),
            CommandSpec(
                name="/scan-compare",
                aliases=("/compare-last-scan",),
                summary="Compare with the last scan",
                description="Compare the current scan context against the last stored scan.",
                category="Scanning",
                implemented=True,
            ),
            CommandSpec(
                name="/findings",
                aliases=("/results",),
                summary="Open the findings workspace",
                description="Inspect the latest or saved scan findings.",
                category="Analysis",
                implemented=False,
            ),
            CommandSpec(
                name="/findings-search",
                aliases=("/results-search",),
                summary="Search findings",
                description="Filter the findings workspace by a search query.",
                category="Analysis",
                implemented=True,
            ),
            CommandSpec(
                name="/findings-baselined",
                aliases=("/baseline-findings", "/results-baselined"),
                summary="Show baselined findings",
                description="Open the view that lists findings filtered out by baselines.",
                category="Analysis",
                implemented=True,
            ),
            CommandSpec(
                name="/suppression-review",
                aliases=("/suppressed-findings", "/results-suppressed"),
                summary="Review suppressed findings",
                description="Inspect findings filtered out by suppressions and manual overrides.",
                category="Analysis",
                implemented=True,
            ),
            CommandSpec(
                name="/findings-filter-severity",
                aliases=("/results-filter-severity",),
                summary="Filter findings by severity",
                description="Show findings for one selected severity bucket.",
                category="Analysis",
                implemented=True,
            ),
            CommandSpec(
                name="/findings-clear-filters",
                aliases=("/results-clear-filters",),
                summary="Clear findings filters",
                description="Remove search and severity filters from the findings workspace.",
                category="Analysis",
                implemented=True,
            ),
            CommandSpec(
                name="/triage-in-review",
                aliases=("/triage-open",),
                summary="Mark finding in review",
                description="Update the selected finding to in_review with an optional reason and note.",
                category="Review",
                implemented=True,
            ),
            CommandSpec(
                name="/triage-triaged",
                aliases=("/triage-resolve",),
                summary="Mark finding triaged",
                description="Update the selected finding to triaged with an optional reason and note.",
                category="Review",
                implemented=True,
            ),
            CommandSpec(
                name="/triage-untriaged",
                aliases=("/triage-reset",),
                summary="Reset finding triage",
                description="Reset the selected finding back to untriaged.",
                category="Review",
                implemented=True,
            ),
            CommandSpec(
                name="/finding-detail",
                aliases=("/finding",),
                summary="Open the finding detail view",
                description="Inspect the currently selected finding in detail.",
                category="Analysis",
                implemented=False,
            ),
            CommandSpec(
                name="/reports",
                aliases=("/report",),
                summary="Open report history and exports",
                description="Browse saved reports and export formats.",
                category="Analysis",
                implemented=False,
            ),
            CommandSpec(
                name="/export-json",
                aliases=("/export-view-json", "/export-current-json"),
                summary="Export the current view as JSON",
                description="Render the current workspace view as JSON.",
                category="Reporting",
                implemented=True,
            ),
            CommandSpec(
                name="/export-sarif",
                aliases=("/export-view-sarif", "/export-current-sarif"),
                summary="Export the current view as SARIF",
                description="Render the current workspace view as SARIF.",
                category="Reporting",
                implemented=True,
            ),
            CommandSpec(
                name="/rules",
                aliases=("/rulebook",),
                summary="Open the rules browser",
                description="Inspect builtin and custom rule packs.",
                category="Analysis",
                implemented=True,
            ),
            CommandSpec(
                name="/rule-detail",
                aliases=("/rule",),
                summary="Open the selected rule detail",
                description="Inspect the selected rule in the browser in detail.",
                category="Analysis",
                implemented=True,
            ),
            CommandSpec(
                name="/rule-pack-next",
                aliases=("/rule-next-pack",),
                summary="Select the next rule pack",
                description="Advance the selected rule pack in the browser.",
                category="Analysis",
                implemented=True,
            ),
            CommandSpec(
                name="/rule-pack-prev",
                aliases=("/rule-prev-pack",),
                summary="Select the previous rule pack",
                description="Move back to the previous rule pack in the browser.",
                category="Analysis",
                implemented=True,
            ),
            CommandSpec(
                name="/rule-pack-select",
                aliases=("/rule-select-pack",),
                summary="Select a rule pack",
                description="Choose a rule pack by index or name.",
                category="Analysis",
                implemented=True,
            ),
            CommandSpec(
                name="/policy",
                aliases=("/gates",),
                summary="Open policy settings",
                description="Inspect policy thresholds and branch behavior.",
                category="Analysis",
                implemented=True,
            ),
            CommandSpec(
                name="/policy-threshold",
                aliases=("/threshold", "/policy-fail-on"),
                summary="Edit the policy threshold",
                description="Set the active severity threshold used by policy gates.",
                category="Analysis",
                implemented=True,
            ),
            CommandSpec(
                name="/policy-branch",
                aliases=("/branch-policy",),
                summary="Review a branch policy",
                description="Inspect the branch-specific policy threshold and overrides.",
                category="Analysis",
                implemented=True,
            ),
            CommandSpec(
                name="/audit-trail",
                aliases=("/audit",),
                summary="Open the audit trail view",
                description="Inspect recorded command, scan, policy, and review actions.",
                category="Analysis",
                implemented=True,
            ),
            CommandSpec(
                name="/manual-overrides",
                aliases=("/overrides",),
                summary="Open manual override management",
                description="Inspect manual overrides that keep findings active or suppressed.",
                category="Analysis",
                implemented=True,
            ),
            CommandSpec(
                name="/mobile",
                aliases=("/android", "/ios",),
                summary="Open mobile analysis views",
                description="Jump into Android or iOS specific inspections.",
                category="Analysis",
                implemented=False,
            ),
            CommandSpec(
                name="/workspace",
                aliases=("/ws",),
                summary="Show the current workspace",
                description="Display the current target, mode, and session context.",
                category="Navigation",
                implemented=False,
            ),
            CommandSpec(
                name="/history",
                aliases=("/recent",),
                summary="Show recent commands and scans",
                description="Review recent actions and scan runs.",
                category="Navigation",
                implemented=False,
            ),
            CommandSpec(
                name="/settings",
                aliases=("/config",),
                summary="Open settings and configuration",
                description="Inspect runtime settings and profiles.",
                category="Configuration",
                implemented=False,
            ),
            CommandSpec(
                name="/clear",
                aliases=("/cls",),
                summary="Clear the terminal surface",
                description="Clear the visible shell content.",
                category="Navigation",
            ),
            CommandSpec(
                name="/back",
                aliases=("/cancel",),
                summary="Return to the previous screen",
                description="Close the current view or cancel a dialog.",
                category="Navigation",
            ),
            CommandSpec(
                name="/exit",
                aliases=("/quit", "/q"),
                summary="Exit the TUI",
                description="Leave the interactive shell.",
                category="Navigation",
            ),
        )
    )
