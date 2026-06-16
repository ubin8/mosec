# MoSec Command System

This document defines the interactive command system for the MoSec terminal UI.

## Goal

The command system turns the terminal into a guided workbench:

- the user types one exact command
- MoSec resolves the command immediately
- MoSec asks follow-up questions only when necessary
- actions are executed inside the app, not by a shell parser

## Syntax Contract

### Canonical form

- Commands start with `/`
- Commands use lowercase letters, digits, and hyphens
- Examples:
  - `/scan`
  - `/scan-quick`
  - `/reports`
  - `/exit`

### Invalid forms

- No shell-style inline fragments
- No command chaining
- No command expansion
- No free-text suffixes after the command token

### Data entry

If a command needs more information, the UI switches to a guided dialog.

Example:

1. User enters `/scan`
2. MoSec asks for target path, mode, and output preference
3. MoSec executes the scan
4. MoSec renders results or opens the findings view

The guided prompt flow is exact and structured. For `/scan`, the first revision collects:

- target path
- scan mode
- output format

## Architecture

### 1. Input capture

- Capture a single command line from the terminal prompt.
- Normalize whitespace and lowercase the command token.
- Reject unsupported syntax early.

### 2. Command resolution

- Match the exact command against a registry.
- Resolve aliases before dispatch.
- Route unknown commands to help or an error state.

### 3. State transition

- Every command should transition the UI to a clear state.
- Example states:
  - home
  - command-help
  - scan-wizard
  - scan-running
  - findings
  - report-view
  - rules-browser
  - settings
- The active session state should remember:
  - current workspace target
  - current scan mode
  - current output format
  - current status message and severity
  - last scan target, mode, and format
  - last executed command
- Destructive actions should require confirmation.
- Guided prompt flows should accept `/back` or `/cancel` to abort the current dialog.

### 4. Execution

- Handlers run inside the MoSec process.
- No command should execute arbitrary shell text.
- Long-running operations must support cancellation and progress updates.

### 5. Rendering

- Each state renders its own panel or screen.
- The command dock stays visually stable.
- User feedback must be visible immediately after command resolution.

## Registry Model

The registry should store:

- canonical command name
- aliases
- short description
- handler function
- required state, if any
- follow-up prompts, if any
- permission or policy requirements, if any

## Command Categories

### Navigation

- `/help`
- `/back`
- `/workspace`
- `/history`
- `/clear`
- `/exit`

### Scanning

- `/scan`
- `/scan-quick`
- `/scan-deep`
- `/scan-web`
- `/scan-mobile`
- `/scan-secrets`
- `/scan-sca`
- `/scan-policy`

### Analysis

- `/findings`
- `/findings-baselined`
- `/findings-search`
- `/findings-filter-severity`
- `/findings-clear-filters`
- `/reports`
- `/rules`
- `/policy`
- `/mobile`

### Configuration

- `/settings`

## Design Constraints

- Commands must stay predictable.
- Commands must remain keyboard-friendly.
- Commands must not depend on shell parsing.
- Commands must not require the user to memorize long argument sequences.
- Scan modes must be obvious from the command name.

## Relationship to the CLI

- The TUI command system is the primary human interface.
- The CLI remains the automation interface.
- The TUI should call into the same underlying scan and reporting engine used by the CLI.

## Implementation Targets

- Command registry
- Exact-match parser
- Alias resolution
- Guided prompts
- History
- Validation
- Screen transitions
- Cancellation support
