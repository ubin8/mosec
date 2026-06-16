# MoSec Roadmap

MoSec is a TUI-first application security workbench. The terminal UI is the primary product surface; the traditional CLI remains available for automation, CI, and scripted scans.

## Product Principles

- TUI is the default entry point.
- Commands are exact slash commands, not shell fragments.
- Guided prompts collect data after a command is recognized.
- The CLI remains stable for non-interactive workflows.
- Reports stay portable through text, JSON, and SARIF.
- Scan modes should be explicit and fast to choose.

## Current Baseline

- [x] TUI home screen with mascot and branding
- [x] Interactive launcher for `mosec`
- [x] CLI automation mode for `mosec scan <path>`
- [x] Text, JSON, and SARIF reporting
- [x] Core repository ingestion, parsing, and analysis pipeline

## Roadmap Phases

### Phase 1: TUI Shell Contract

- [x] Define the exact slash-command grammar
- [x] Implement a command registry with aliases
- [x] Implement guided prompts for commands that need context
- [x] Add command history and recall
- [x] Add help and command discovery
- [x] Add a session state model for workspace, mode, and last scan
- [x] Add a consistent notification/status area
- [x] Add a cancellation and confirmation flow

### Phase 2: Scan Workflows

- [x] `/scan` guided scan entry
- [x] `/scan-quick` fast workspace scan
- [x] `/scan-deep` full analysis scan
- [x] `/scan-web` web-focused scan mode
- [x] `/scan-mobile` mobile-focused scan mode
- [x] `/scan-secrets` secrets-only mode
- [x] `/scan-sca` dependency-only mode
- [x] `/scan-policy` policy and baseline-only mode
- [x] Scan target selection from the TUI
- [x] Scan progress and cancellation feedback
- [x] Repeat last scan
- [x] Compare current scan to last scan

### Phase 3: Findings Workspace

- [x] Findings list view
- [x] Finding detail view
- [x] Severity grouping
- [x] Search and filters
- [x] Baseline-aware views
- [x] Suppression review from the UI
- [x] Triage actions from the UI
- [x] Export current view to JSON or SARIF

### Phase 4: Rules and Policy

- [ ] Rules browser
- [ ] Rule pack selection
- [ ] Rule detail view
- [ ] Policy threshold editor
- [ ] Branch-specific policy review
- [ ] Audit trail view
- [ ] Manual override management
- [ ] Suppression expiry handling in the UI

### Phase 5: Mobile Focus

- [ ] Android manifest inspection view
- [ ] Android component risk summary
- [ ] Android permission review
- [ ] iOS entitlements inspection
- [ ] iOS ATS and URL scheme checks
- [ ] Mobile-specific findings filters
- [ ] Mobile scan mode summaries

### Phase 6: Integrations

- [ ] GitHub Actions guidance
- [ ] GitLab CI guidance
- [ ] PR-comment export mode
- [ ] Artifact export helpers
- [ ] SARIF-first code host workflows
- [ ] Local API surface for external tools

### Phase 7: Platform Growth

- [ ] Dashboard view
- [ ] Team and project model
- [ ] Roles and permissions
- [ ] Aggregated trend views
- [ ] Audit retention model
- [ ] Advanced reachability and exploitability scoring
- [ ] AI-assisted remediation suggestions

## Definition of Done for the TUI-first Product

- `mosec` opens a usable command-driven terminal workspace.
- The most common security tasks can be started through exact slash commands.
- Interactive workflows do not require shell-style free text.
- Automation still works through the CLI.
- Scan results can be reviewed, filtered, and exported from the terminal.
