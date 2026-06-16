from __future__ import annotations

import locale
import sys
from importlib import resources
from shutil import get_terminal_size
from typing import Callable

from .commands import CommandHistory, CommandOutcome, PromptSpec, build_default_command_registry, normalize_command_text
from .state import SessionState

try:  # pragma: no cover - optional on non-Unix platforms
    import curses
except ImportError:  # pragma: no cover - fallback for environments without curses
    curses = None

BRAND_FALLBACK = (
    "███╗   ███╗ ██████╗ ███████╗███████╗ ██████╗\n"
    "████╗ ████║██╔═══██╗██╔════╝██╔════╝██╔════╝\n"
    "██╔████╔██║██║   ██║███████╗█████╗  ██║\n"
    "██║╚██╔╝██║██║   ██║╚════██║██╔══╝  ██║\n"
    "██║ ╚═╝ ██║╚██████╔╝███████║███████╗╚██████╗\n"
    "╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚══════╝ ╚═════╝"
)

MASCOT_FALLBACK = (
    "   ▄█████▄\n"
    "  ██▀███▀██\n"
    " ▄█████████▄\n"
    "▀▀█████████▀▀\n"
    "  █████████\n"
    "  ▀▀▀███▀▀▀"
)


def _load_text_asset(filename: str, fallback: str) -> str:
    try:
        asset = resources.files("mosec").joinpath(filename)
        return asset.read_text(encoding="utf-8").strip("\n")
    except (FileNotFoundError, ModuleNotFoundError, OSError):  # pragma: no cover - runtime fallback
        return fallback


def load_brand_art() -> str:
    return _load_text_asset("ascii-art.txt", BRAND_FALLBACK)


def load_mascot_art() -> str:
    return _load_text_asset("geist_art.txt", MASCOT_FALLBACK)


def _render_side_by_side(left: list[str], right: list[str], gap: int = 4) -> list[str]:
    left_width = max((len(line) for line in left), default=0)
    right_width = max((len(line) for line in right), default=0)
    rows = max(len(left), len(right))
    rendered: list[str] = []
    for index in range(rows):
        left_line = left[index] if index < len(left) else ""
        right_line = right[index] if index < len(right) else ""
        rendered.append(f"{left_line.ljust(left_width)}{' ' * gap}{right_line}".rstrip())
    return rendered


def _separator(width: int) -> str:
    return "─" * max(width, 1)


def _center_line(line: str, width: int) -> str:
    return line.center(width)[:width]


def _build_home_screen_lines(
    width: int | None = None,
    height: int | None = None,
    *,
    state: SessionState | None = None,
) -> list[str]:
    terminal_size = get_terminal_size((120, 36))
    width = width or terminal_size.columns
    height = height or terminal_size.lines
    state = state or SessionState()
    art_lines = _render_side_by_side(
        load_mascot_art().splitlines(),
        load_brand_art().splitlines(),
        gap=16,
    )
    art_width = max((len(line) for line in art_lines), default=0)
    left_pad = max((width - art_width) // 2, 0)

    centered_art = [f"{' ' * left_pad}{line}" for line in art_lines]
    status_line = _center_line(f"Status [{state.status_kind.upper()}]: {state.status_text}", width)
    prompt_dock_height = 3
    available_space = max(height - len(centered_art) - prompt_dock_height, 0)
    top_pad = min(max(height // 12, 2), available_space)
    gap_lines = max(available_space - top_pad, 0)

    lines: list[str] = []
    lines.extend("" for _ in range(top_pad))
    lines.extend(centered_art)
    lines.append("")
    lines.append(status_line)
    lines.extend("" for _ in range(gap_lines))
    return lines


def render_home_screen(width: int | None = None, height: int | None = None, *, state: SessionState | None = None) -> str:
    return "\n".join(_build_home_screen_lines(width=width, height=height, state=state))


def _write_prompt_dock(width: int) -> None:
    separator = _separator(width)
    sys.stdout.write(separator + "\n")
    sys.stdout.write("> \n")
    sys.stdout.write(separator + "\n")
    sys.stdout.write("\033[2A\r\033[2C")
    sys.stdout.flush()


def _format_prompt(spec: PromptSpec) -> str:
    label = spec.question
    if spec.default is not None:
        label += f" [{spec.default}]"
    if spec.choices:
        label += f" ({'/'.join(spec.choices)})"
    return f"{label}: "


def _normalize_prompt_answer(spec: PromptSpec, raw: str) -> str:
    value = raw.strip()
    if not value and spec.default is not None:
        return spec.default
    if spec.choices:
        lowered = value.lower()
        if lowered in spec.choices:
            return lowered
        if spec.default is not None:
            return spec.default
    return value


def _is_cancel_request(raw: str) -> bool:
    normalized = normalize_command_text(raw)
    return normalized in {"/back", "/cancel"}


def _normalize_confirmation_answer(raw: str) -> bool:
    normalized = raw.strip().lower()
    return normalized in {"y", "yes"}


def _guided_scan_summary(answers: dict[str, str]) -> tuple[str, ...]:
    return (
        "Guided scan configured.",
        f"Target: {answers.get('target', '.')}",
        f"Mode: {answers.get('mode', 'deep')}",
        f"Format: {answers.get('format', 'text')}",
        "The scan engine wiring will be expanded in the next roadmap chunk.",
    )


def _guided_scan_prompt_steps(state: SessionState) -> tuple[PromptSpec, ...]:
    return state.scan_prompt_specs()


def _scan_mode_from_command_name(command_name: str) -> str:
    if command_name == "/scan":
        return "guided"
    if command_name.startswith("/scan-"):
        return command_name.removeprefix("/scan-")
    return "deep"


def _scan_summary_lines(mode: str, state: SessionState) -> tuple[str, ...]:
    return (
        f"{mode.replace('-', ' ').title()} scan prepared.",
        f"Target: {state.workspace}",
        f"Mode: {state.scan_mode}",
        f"Format: {state.output_format}",
    )


def _collect_prompt_answers(
    prompt_steps: tuple[PromptSpec, ...],
    *,
    input_func: Callable[[str], str],
) -> dict[str, str] | None:
    answers: dict[str, str] = {}
    for spec in prompt_steps:
        raw = input_func(_format_prompt(spec))
        if _is_cancel_request(raw):
            return None
        answers[spec.key] = _normalize_prompt_answer(spec, raw)
    return answers


def _session_state_lines(state: SessionState) -> tuple[str, ...]:
    return state.summary_lines()


def _status_lines(state: SessionState) -> tuple[str, ...]:
    return (
        f"Status [{state.status_kind.upper()}]: {state.status_text}",
        f"Workspace: {state.workspace} | Mode: {state.scan_mode} | Format: {state.output_format}",
    )


def _emit_status_lines(state: SessionState, output_func: Callable[[str], None]) -> None:
    for line in _status_lines(state):
        output_func(line)


def _prompt_confirmation(
    question: str,
    *,
    input_func: Callable[[str], str],
) -> bool:
    raw = input_func(f"{question} [y/N]: ")
    if _is_cancel_request(raw):
        return False
    return _normalize_confirmation_answer(raw)


def _curses_prompt_confirmation(
    stdscr: "curses.window",
    *,
    row: int,
    width: int,
    question: str,
) -> bool:
    prompt = f"{question} [y/N]: "
    try:
        stdscr.move(row, 0)
        stdscr.clrtoeol()
        stdscr.addstr(row, 0, prompt[:width])
        stdscr.refresh()
    except curses.error:  # pragma: no cover - defensive terminal guard
        pass
    answer = _curses_read_line(stdscr, row, min(len(prompt), max(width - 1, 0)), max(width - len(prompt) - 1, 0))
    if _is_cancel_request(answer):
        return False
    return _normalize_confirmation_answer(answer)


def _curses_read_line(stdscr: "curses.window", y: int, x: int, max_width: int) -> str:
    value = ""
    while True:
        try:
            ch = stdscr.get_wch()
        except curses.error:  # pragma: no cover - defensive terminal guard
            continue
        if ch in {"\n", "\r", curses.KEY_ENTER}:
            break
        if ch in {curses.KEY_BACKSPACE, "\b", "\x7f"}:
            value = value[:-1]
        elif isinstance(ch, str) and ch.isprintable():
            if len(value) < max_width:
                value += ch
        visible = value[:max_width]
        stdscr.move(y, x)
        stdscr.clrtoeol()
        stdscr.addstr(y, x, visible)
        stdscr.move(y, x + len(visible))
        stdscr.refresh()
    return value


def _curses_collect_prompt_answers(
    stdscr: "curses.window",
    prompt_steps: tuple[PromptSpec, ...],
    *,
    row: int,
    width: int,
    height: int,
) -> dict[str, str]:
    answers: dict[str, str] = {}
    current_row = row
    for spec in prompt_steps:
        if current_row >= height:
            current_row = max(height - 1, 0)
        question = _format_prompt(spec)
        question_width = max(width - len(question) - 1, 0)
        try:
            stdscr.move(current_row, 0)
            stdscr.clrtoeol()
            stdscr.addstr(current_row, 0, question[:width])
            stdscr.refresh()
        except curses.error:  # pragma: no cover - defensive terminal guard
            pass
        answer = _curses_read_line(
            stdscr,
            current_row,
            min(len(question), max(width - 1, 0)),
            question_width,
        )
        answers[spec.key] = _normalize_prompt_answer(spec, answer)
        current_row += 1
    return answers


def _launch_home_screen_curses(registry, state: SessionState) -> int:
    locale.setlocale(locale.LC_ALL, "")

    def _draw(stdscr: "curses.window") -> int:
        curses.curs_set(1)
        stdscr.keypad(True)
        stdscr.erase()
        height, width = stdscr.getmaxyx()

        lines = _build_home_screen_lines(width=width, height=height, state=state)
        prompt_row = min(max(height // 2 - 2, 8), max(height - 3, 0))

        for row, line in enumerate(lines[:prompt_row]):
            if row >= height:
                break
            try:
                stdscr.addstr(row, 0, line[:width])
            except curses.error:  # pragma: no cover - skip partial terminal writes
                pass

        separator = _separator(width)
        try:
            stdscr.addstr(prompt_row, 0, separator[:width])
            stdscr.addstr(prompt_row + 1, 0, "> ")
            stdscr.addstr(prompt_row + 2, 0, separator[:width])
        except curses.error:  # pragma: no cover - skip partial terminal writes
            pass
        stdscr.move(prompt_row + 1, 2)
        stdscr.refresh()

        choice = _curses_read_line(stdscr, prompt_row + 1, 2, max(width - 2, 0))
        if not choice.strip():
            return 0
        state.remember_command(choice)
        outcome = registry.execute(choice)

        if outcome.kind == "help":
            state.set_status("Help opened.")
        elif outcome.kind == "invalid":
            state.set_status("Invalid command syntax.", kind="warning")
        elif outcome.kind == "unknown":
            state.set_status(f"Unknown command: {choice}", kind="warning")
        elif outcome.kind == "workspace" and outcome.command is not None and outcome.command.name == "/workspace":
            state.set_status("Workspace overview displayed.")
        elif outcome.kind == "workspace" and outcome.command is not None and outcome.command.name == "/history":
            state.set_status("Recent commands shown.")
        elif outcome.kind == "scan" and outcome.command is not None:
            mode = _scan_mode_from_command_name(outcome.command.name)
            if outcome.command.name != "/scan":
                state.record_scan(state.workspace, mode, state.output_format)
                state.set_status(f"{mode.replace('-', ' ').title()} scan prepared for {state.workspace}", kind="success")
            else:
                state.set_status("Scan mode selected: guided")
        elif outcome.kind == "wizard":
            state.set_status("Guided scan wizard started.")
        elif outcome.kind == "confirm" and outcome.confirmation is not None:
            confirmed = _curses_prompt_confirmation(
                stdscr,
                row=min(prompt_row + 3, max(height - 1, 0)),
                width=width,
                question=outcome.confirmation.question,
            )
            if not confirmed:
                state.set_status("Action canceled.", kind="warning")
                lines_to_render = ("Action canceled.",)
                message_row = min(prompt_row + 4, max(height - 1, 0))
                for offset, line in enumerate(lines_to_render):
                    if message_row + offset >= height:
                        break
                    try:
                        stdscr.addstr(message_row + offset, 0, line[:width])
                    except curses.error:  # pragma: no cover - skip partial terminal writes
                        pass
                stdscr.refresh()
                return 0
            if outcome.confirmation.action == "clear":
                stdscr.erase()
                stdscr.refresh()
                state.set_status("Screen cleared.")
                return 0
            if outcome.confirmation.action == "exit":
                state.set_status("Exiting MoSec.")
                return 0

        message_row = min(prompt_row + 4, max(height - 1, 0))
        lines_to_render: tuple[str, ...] = outcome.message_lines
        if outcome.prompt_steps:
            answers = _curses_collect_prompt_answers(
                stdscr,
                _guided_scan_prompt_steps(state) if outcome.command and outcome.command.name == "/scan" else outcome.prompt_steps,
                row=message_row,
                width=width,
                height=height,
            )
            if answers is None:
                state.set_status("Guided scan canceled.", kind="warning")
                lines_to_render = ("Guided scan canceled.",)
                for offset, line in enumerate(lines_to_render):
                    if message_row + offset >= height:
                        break
                    try:
                        stdscr.addstr(message_row + offset, 0, line[:width])
                    except curses.error:  # pragma: no cover - skip partial terminal writes
                        pass
                stdscr.refresh()
                return 0
            if outcome.command and outcome.command.name == "/scan":
                state.record_scan(
                    target=answers.get("target", state.workspace),
                    mode=answers.get("mode", state.scan_mode),
                    output_format=answers.get("format", state.output_format),
                )
                state.set_status(
                    f"Guided scan prepared for {state.workspace}",
                    kind="success",
                )
            lines_to_render = outcome.message_lines + _guided_scan_summary(answers)
        elif outcome.command and outcome.command.name == "/workspace":
            lines_to_render = _session_state_lines(state)
        elif outcome.command and outcome.command.name in {"/scan-quick", "/scan-deep", "/scan-web", "/scan-mobile", "/scan-secrets", "/scan-sca", "/scan-policy"}:
            mode = _scan_mode_from_command_name(outcome.command.name)
            state.record_scan(state.workspace, mode, state.output_format)
            state.set_status(f"{mode.replace('-', ' ').title()} scan prepared for {state.workspace}", kind="success")
            state.last_command = outcome.command.name
            lines_to_render = outcome.message_lines + _scan_summary_lines(mode, state)

        for offset, line in enumerate(lines_to_render):
            if message_row + offset >= height:
                break
            try:
                stdscr.addstr(message_row + offset, 0, line[:width])
            except curses.error:  # pragma: no cover - skip partial terminal writes
                pass
        stdscr.refresh()
        return 0

    return curses.wrapper(_draw)


def launch_home_screen(
    *,
    width: int | None = None,
    height: int | None = None,
    input_func: Callable[[str], str] = input,
    output_func: Callable[[str], None] = print,
    interactive: bool = False,
) -> int:
    registry = build_default_command_registry()
    history = CommandHistory()
    state = SessionState()
    terminal_size = get_terminal_size((120, 36))
    width = width or terminal_size.columns
    height = height or terminal_size.lines
    if interactive:
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()
        if curses is not None and sys.stdin.isatty() and sys.stdout.isatty():
            return _launch_home_screen_curses(registry, state)
    output_func(render_home_screen(width=width, height=height, state=state))
    if not interactive:
        return 0

    _write_prompt_dock(width)
    choice = input_func("").strip()
    if not choice:
        return 0
    history.add(choice)
    state.remember_command(choice)
    if choice in {"/history", "/recent"}:
        output_func("Recent commands:")
        for item in history.recent():
            output_func(f"  {item}")
        state.set_status("Recent commands shown.")
        _emit_status_lines(state, output_func)
        return 0
    outcome = registry.execute(choice)
    sys.stdout.write("\n")
    sys.stdout.flush()

    if outcome.kind == "help":
        state.set_status("Help opened.")
    elif outcome.kind == "invalid":
        state.set_status("Invalid command syntax.", kind="warning")
    elif outcome.kind == "unknown":
        state.set_status(f"Unknown command: {choice}", kind="warning")
    elif outcome.kind == "workspace" and outcome.command is not None and outcome.command.name == "/workspace":
        state.set_status("Workspace overview displayed.")
    elif outcome.kind == "workspace" and outcome.command is not None and outcome.command.name == "/history":
        state.set_status("Recent commands shown.")
    elif outcome.kind == "scan" and outcome.command is not None:
        mode = _scan_mode_from_command_name(outcome.command.name)
        if outcome.command.name != "/scan":
            state.record_scan(state.workspace, mode, state.output_format)
            state.set_status(f"{mode.replace('-', ' ').title()} scan prepared for {state.workspace}", kind="success")
        else:
            state.set_status("Scan mode selected: guided")
    elif outcome.kind == "wizard":
        state.set_status("Guided scan wizard started.")
    elif outcome.kind == "confirm" and outcome.confirmation is not None:
        confirmed = _prompt_confirmation(outcome.confirmation.question, input_func=input_func)
        if not confirmed:
            state.set_status("Action canceled.", kind="warning")
            _emit_status_lines(state, output_func)
            output_func("Action canceled.")
            return 0
        if outcome.confirmation.action == "clear":
            output_func("\033[2J\033[H")
            state.set_status("Screen cleared.")
            _emit_status_lines(state, output_func)
            output_func("Screen cleared.")
            return 0
        if outcome.confirmation.action == "exit":
            state.set_status("Exiting MoSec.")
            _emit_status_lines(state, output_func)
            output_func("Exiting MoSec.")
            return 0

    lines_to_render: tuple[str, ...] = outcome.message_lines
    if outcome.prompt_steps:
        prompt_steps = _guided_scan_prompt_steps(state) if outcome.command and outcome.command.name == "/scan" else outcome.prompt_steps
        answers = _collect_prompt_answers(prompt_steps, input_func=input_func)
        if answers is None:
            state.set_status("Guided scan canceled.", kind="warning")
            _emit_status_lines(state, output_func)
            output_func("Guided scan canceled.")
            return 0
        if outcome.command and outcome.command.name == "/scan":
            state.record_scan(
                target=answers.get("target", state.workspace),
                mode=answers.get("mode", state.scan_mode),
                output_format=answers.get("format", state.output_format),
            )
            state.set_status(f"Guided scan prepared for {state.workspace}", kind="success")
        lines_to_render = outcome.message_lines + _guided_scan_summary(answers)
    elif outcome.command and outcome.command.name == "/workspace":
        lines_to_render = _session_state_lines(state)
    elif outcome.command and outcome.command.name in {"/scan-quick", "/scan-deep", "/scan-web", "/scan-mobile", "/scan-secrets", "/scan-sca", "/scan-policy"}:
        mode = _scan_mode_from_command_name(outcome.command.name)
        state.record_scan(state.workspace, mode, state.output_format)
        state.set_status(f"{mode.replace('-', ' ').title()} scan prepared for {state.workspace}", kind="success")
        lines_to_render = outcome.message_lines + _scan_summary_lines(mode, state)
    _emit_status_lines(state, output_func)
    for line in lines_to_render:
        output_func(line)
    if outcome.should_exit:
        return 0
    return 0
