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
    "    ▓▓▓▓▓▓\n"
    "  ▓████████▓\n"
    " ▓██████████▓\n"
    "▓████████████▓\n"
    "▓███▓▓▓▓▓▓███▓\n"
    "▓██▓░░░░░░▓██▓\n"
    "▓██▓░▓██▓░▓██▓\n"
    " ▓██▓░▓▓░▓██▓\n"
    "  ▓██▓▓▓▓██▓\n"
    "   ▓██████▓"
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
    return _load_text_asset("mascot.txt", MASCOT_FALLBACK)


def _render_side_by_side(left: list[str], right: list[str], gap: int = 4) -> list[str]:
    left_width = max((len(line) for line in left), default=0)
    right_width = max((len(line) for line in right), default=0)
    rows = max(len(left), len(right))
    rendered: list[str] = []
    for index in range(rows):
        left_line = left[index] if index < len(left) else ""
        right_line = right[index] if index < len(right) else ""
        rendered.append(
            f"{left_line.ljust(left_width)}{' ' * gap}{right_line.ljust(right_width)}".rstrip()
        )
    return rendered


def _border(width: int, left: str, fill: str, right: str) -> str:
    body = max(width - 2, 0)
    return f"{left}{fill * body}{right}" if body > 0 else left + right


def _center(text: str, width: int) -> str:
    if len(text) >= width:
        return text
    pad_left = (width - len(text)) // 2
    return f"{' ' * pad_left}{text}"


def render_home_screen(width: int | None = None) -> str:
    width = width or max(get_terminal_size((120, 36)).columns, 96)
    content_width = min(width, 110)

    mascot_lines = load_mascot_art().splitlines()
    brand_lines = load_brand_art().splitlines()
    header_lines = _render_side_by_side(mascot_lines, brand_lines, gap=6)

    lines: list[str] = []
    lines.append(_border(content_width, "┌", "─", "┐"))
    lines.append(f"│{_center('', content_width - 2):<{content_width - 2}}│")
    for line in header_lines:
        lines.append(f"│ {line.ljust(content_width - 3)}│")
    lines.append(f"│{_center('', content_width - 2):<{content_width - 2}}│")
    lines.append(_border(content_width, "├", "─", "┤"))
    lines.append(f"│{' >'.ljust(content_width - 2)}│")
    lines.append(_border(content_width, "└", "─", "┘"))
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

    while True:
        choice = input_func("mosec> ").strip().lower()
        if choice in {"q", "quit", "exit"}:
            return 0
        if choice in {"h", "help", "?"}:
            output_func("Shortcuts: s = scan current directory, q = quit, ? = help")
            continue
        if choice in {"s", "scan"}:
            output_func("Run `mosec scan .` to scan the current directory.")
            return 0
        if choice == "":
            continue
        output_func("Unknown command. Type `?` for help.")
