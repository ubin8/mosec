# Terminal UI

MoSec starts with a terminal home screen when you run `mosec` without arguments.

## What it is for

- Fast orientation in the tool
- Clear entry point for people using the scanner interactively
- A visual front door for scan, rules, report, and mobile workflows

## Current screen

The first version shows:

- a compact mascot on the left
- the MoSec wordmark on the right
- a minimal prompt dock beneath the art block

## Keyboard behavior

- `q` exits the interactive mode
- `h` shows help
- `s` prints a quick scan hint

## Non-interactive behavior

If MoSec is started without a TTY, it prints the screen once and exits cleanly.

## Prompt style

- The prompt is a plain `>` prompt.
- The art block is not framed by a box.
- Separator lines appear above and below the prompt area.

## Relationship to the CLI

- `mosec` opens the home screen
- `mosec scan <path>` runs the scanner directly
- `mosec version` prints the installed version
