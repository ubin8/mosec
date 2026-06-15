from __future__ import annotations

from importlib import resources
from shutil import get_terminal_size
from textwrap import dedent
from typing import Callable

ASCII_FALLBACK = dedent(
    """
    ███╗   ███╗ ██████╗ ███████╗███████╗ ██████╗
    ████╗ ████║██╔═══██╗██╔════╝██╔════╝██╔════╝
    ██╔████╔██║██║   ██║███████╗█████╗  ██║
    ██║╚██╔╝██║██║   ██║╚════██║██╔══╝  ██║
    ██║ ╚═╝ ██║╚██████╔╝███████║███████╗╚██████╗
    ╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚══════╝ ╚═════╝
    """
).strip("\n")


def load_ascii_art() -> str:
    try:
        asset = resources.files("mosec").joinpath("ascii-art.txt")
        return asset.read_text(encoding="utf-8").strip("\n")
    except (FileNotFoundError, ModuleNotFoundError, OSError):  # pragma: no cover - runtime fallback
        return ASCII_FALLBACK


def _center_line(text: str, width: int) -> str:
    if len(text) >= width:
        return text
    padding = (width - len(text)) // 2
    return f"{' ' * padding}{text}"


def _box_line(width: int, left: str, middle: str, right: str) -> str:
    body_width = max(width - 2, 0)
    if body_width == 0:
        return left + right
    return f"{left}{middle * body_width}{right}"


def render_home_screen(width: int | None = None) -> str:
    width = width or max(get_terminal_size((120, 36)).columns, 88)
    inner_width = min(width, 110)
    art = load_ascii_art().splitlines()
    title = "MoSec"
    subtitle = "CLI-first application security scanner"
    tabs = "Scan | Rules | Reports | Mobile | Settings"
    shortcuts = "Enter: quick tips    s: scan current dir    q: quit"
    status = "Healthy"

    lines: list[str] = []
    lines.append(_box_line(inner_width, "┌", "─", "┐"))
    lines.append(f"│{_center_line(f'{title}  {status}', inner_width - 2):<{inner_width - 2}}│")
    lines.append(f"│{_center_line(subtitle, inner_width - 2):<{inner_width - 2}}│")
    lines.append(f"│{_center_line('', inner_width - 2):<{inner_width - 2}}│")
    for art_line in art:
        lines.append(f"│{_center_line(art_line, inner_width - 2):<{inner_width - 2}}│")
    lines.append(f"│{_center_line('', inner_width - 2):<{inner_width - 2}}│")
    lines.append(f"│{_center_line(tabs, inner_width - 2):<{inner_width - 2}}│")
    lines.append(f"│{_center_line('', inner_width - 2):<{inner_width - 2}}│")
    lines.append(f"│{_center_line(shortcuts, inner_width - 2):<{inner_width - 2}}│")
    lines.append(_box_line(inner_width, "└", "─", "┘"))
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
    output_func("")
    output_func("Type `s` for a quick scan hint, `h` for help, or `q` to exit.")
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
