# Terminal UI

MoSec starts with a terminal home screen when you run `mosec` without arguments.

## What it is for

- Fast orientation in the tool
- A command-driven interactive workbench
- A visual front door for scan, rules, report, mobile, and settings workflows

## Current screen

The first version shows:

- a compact mascot on the left
- the MoSec wordmark on the right
- a minimal prompt dock beneath the art block

## Command model

- The interactive shell is designed around exact slash commands.
- The command list is defined in [TUI Command List](tui-command-list.md).
- The routing model is defined in [Command System](command-system.md).

Examples:

- `/help`
- `/scan`
- `/scan-quick`
- `/scan-web`
- `/scan-mobile`

## Non-interactive behavior

If MoSec is started without a TTY, it prints the screen once and exits cleanly.

## Prompt style

- The prompt is a plain `>` prompt.
- The art block is not framed by a box.
- Separator lines appear above and below the prompt area.

## Relationship to the CLI

- `mosec` opens the home screen
- `mosec scan <path>` runs the automation CLI directly
- `mosec version` prints the installed version
