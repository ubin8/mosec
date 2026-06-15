from __future__ import annotations

from importlib import resources
from shutil import get_terminal_size
from typing import Callable

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


def _build_home_screen_lines(width: int | None = None, height: int | None = None) -> list[str]:
    terminal_size = get_terminal_size((120, 36))
    width = width or terminal_size.columns
    height = height or terminal_size.lines
    art_lines = _render_side_by_side(
        load_mascot_art().splitlines(),
        load_brand_art().splitlines(),
        gap=16,
    )
    art_width = max((len(line) for line in art_lines), default=0)
    left_pad = max((width - art_width) // 2, 0)

    centered_art = [f"{' ' * left_pad}{line}" for line in art_lines]
    prompt_dock_height = 3
    gap_lines = max(6, height // 8)
    block_height = len(centered_art) + gap_lines + prompt_dock_height
    top_pad = max((height - block_height) // 2, 0)

    lines: list[str] = []
    lines.extend("" for _ in range(top_pad))
    lines.extend(centered_art)
    lines.extend("" for _ in range(gap_lines))
    return lines


def render_home_screen(width: int | None = None, height: int | None = None) -> str:
    return "\n".join(_build_home_screen_lines(width=width, height=height))


def launch_home_screen(
    *,
    width: int | None = None,
    height: int | None = None,
    input_func: Callable[[str], str] = input,
    output_func: Callable[[str], None] = print,
    interactive: bool = False,
) -> int:
    terminal_size = get_terminal_size((120, 36))
    width = width or terminal_size.columns
    height = height or terminal_size.lines
    if interactive:
        output_func("\033[2J\033[H")
    output_func(render_home_screen(width=width, height=height))
    if not interactive:
        return 0

    separator = _separator(width)
    output_func(separator)
    choice = input_func("> ").strip().lower()
    output_func(separator)

    if choice in {"q", "quit", "exit", ""}:
        return 0
    if choice in {"h", "help", "?"}:
        output_func("Shortcuts: s = scan current directory, q = quit, ? = help")
        return 0
    if choice in {"s", "scan"}:
        output_func("Run `mosec scan .` to scan the current directory.")
        return 0

    output_func("Unknown command. Type `?` for help.")
    return 0
