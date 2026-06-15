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

PROMPT_SEPARATOR = "─" * 72


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


def render_home_screen(width: int | None = None) -> str:
    width = width or max(get_terminal_size((120, 36)).columns, 96)
    content_width = min(width, 110)
    art_lines = _render_side_by_side(
        load_mascot_art().splitlines(),
        load_brand_art().splitlines(),
        gap=12,
    )
    art_width = max((len(line) for line in art_lines), default=0)
    left_pad = max((content_width - art_width) // 2, 0)

    lines: list[str] = []
    lines.extend(f"{' ' * left_pad}{line}" for line in art_lines)
    lines.append("")
    return "\n".join(lines)


def launch_home_screen(
    *,
    width: int | None = None,
    input_func: Callable[[str], str] = input,
    output_func: Callable[[str], None] = print,
    interactive: bool = False,
) -> int:
    if interactive:
        output_func("\033[2J\033[H")
    output_func(render_home_screen(width=width))
    if not interactive:
        return 0

    output_func(PROMPT_SEPARATOR.ljust(width or 72, "─"))
    choice = input_func("> ").strip().lower()

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
