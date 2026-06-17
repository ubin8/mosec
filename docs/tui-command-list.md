# TUI Command List

This is the command contract for the interactive MoSec terminal shell. Commands are exact slash commands. They do not accept shell-style free text in the command itself.

## Command Rules

- Commands start with `/`.
- Commands are exact matches, with a small alias list where useful.
- Data entry happens after command resolution in guided prompts.
- A command never executes arbitrary shell input.
- If a command needs additional context, the UI asks follow-up questions in a controlled flow.

## Core Commands

| Command | Aliases | Purpose | Follow-up Flow |
| --- | --- | --- | --- |
| `/help` | `/h`, `/` | Show the command list and current shortcuts | None |
| `/scan` | `/s` | Start the guided scan wizard | Ask for target, scan mode, and output format |
| `/scan-quick` | `/quick-scan` | Fast scan of the current workspace | Optional confirm step |
| `/scan-deep` | `/deep-scan` | Full analysis scan | Optional confirm step |
| `/scan-web` | `/web-scan` | Web-focused scan mode | Optional target confirmation |
| `/scan-mobile` | `/mobile-scan` | Mobile-focused scan mode | Optional target confirmation |
| `/scan-secrets` | `/secrets-scan` | Secrets-only scan | None or current workspace confirmation |
| `/scan-sca` | `/deps-scan`, `/sca-scan` | Dependency-only scan | None or current workspace confirmation |
| `/scan-policy` | `/policy-scan` | Policy, baseline, and suppression review | Ask for current workspace or report |
| `/findings` | `/results` | Open the findings workspace | Choose latest, current, or saved scan |
| `/export-json` | `/export-view-json`, `/export-current-json` | Export the current view as JSON | None |
| `/export-sarif` | `/export-view-sarif`, `/export-current-sarif` | Export the current view as SARIF | None |
| `/reports` | `/report` | Open report history and export actions | Choose output format or saved report |
| `/rules` | `/rulebook` | Open rules and rule-pack browser | Choose builtin or custom rule packs |
| `/rule-detail` | `/rule` | Open the selected rule detail | None |
| `/rule-pack-next` | `/rule-next-pack` | Select the next rule pack | None |
| `/rule-pack-prev` | `/rule-prev-pack` | Select the previous rule pack | None |
| `/rule-pack-select` | `/rule-select-pack` | Select a rule pack by index or name | Ask for a pack identifier |
| `/policy` | `/gates` | Open policy and threshold settings | Choose branch or workspace policy |
| `/policy-threshold` | `/threshold`, `/policy-fail-on` | Edit the active policy threshold | Ask for low, medium, high, critical, or none |
| `/mobile` | `/android`, `/ios` | Jump to mobile analysis views | Choose platform |
| `/workspace` | `/ws` | Show current workspace context | None |
| `/history` | `/recent` | Show recent commands and scans | None |
| `/settings` | `/config` | Open settings and configuration | Choose runtime or profile settings |
| `/clear` | `/cls` | Clear the terminal surface | None |
| `/back` | `/cancel` | Return to the previous screen or cancel a dialog | None |
| `/exit` | `/quit`, `/q` | Exit the TUI | None |

## Scan Command Family

The scan family is intentionally split into exact commands instead of a single command with inline arguments.

- `/scan` is the guided entry point.
- `/scan-quick` is the fastest default.
- `/scan-deep` is the most thorough general scan.
- `/scan-web` focuses on web application issues.
- `/scan-mobile` focuses on Android and iOS issues.
- `/scan-secrets` checks only secrets and high-signal credential patterns.
- `/scan-sca` checks only dependency risk.
- `/scan-policy` focuses on baselines, suppressions, and policy gates.

This keeps the command model deterministic and easy to learn.

## Behavior Notes

- Commands should feel like actions, not shell syntax.
- The UI should never require a user to type `scan quick` or `scan deep`.
- All context-dependent questions should appear after the command is recognized.
- The same command should behave consistently across light and dark terminals.
- The command list should always be available through `/help`.
