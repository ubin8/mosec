from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import (
    ConfigError,
    ScanConfig,
    build_default_scan_config,
    load_scan_config_file,
    merge_scan_config,
)
from .policy import findings_exceed_threshold
from .reporting import render_json, render_sarif, render_text
from .scanner import scan_repository
from .tui import launch_home_screen


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mosec",
        description="MoSec terminal workbench and automation CLI",
        epilog=(
            "Examples:\n"
            "  mosec\n"
            "  mosec scan .\n"
            "  mosec scan . --format json --fail-on high\n"
            "  mosec version"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a repository or directory")
    scan.add_argument("path", type=Path, help="Path to scan")
    scan.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default=None,
        help="Output format",
    )
    scan.add_argument(
        "--config",
        type=Path,
        help="Path to TOML config file",
    )
    scan.add_argument(
        "--branch",
        help="Current branch name for branch-specific policy rules",
    )
    scan.add_argument(
        "--include",
        action="append",
        default=[],
        help="Include pattern, may be repeated",
    )
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Exclude pattern, may be repeated",
    )
    scan.add_argument(
        "--baseline",
        type=Path,
        help="Path to baseline file",
    )
    scan.add_argument(
        "--suppressions",
        type=Path,
        help="Path to suppression file",
    )
    scan.add_argument(
        "--overrides",
        type=Path,
        help="Path to manual override file",
    )
    scan.add_argument(
        "--fail-on",
        choices=("low", "medium", "high", "critical"),
        help="Fail the scan on or above this severity",
    )
    scan.add_argument(
        "--max-noise",
        action="store_true",
        help="Keep additional diagnostics and discovery notes",
    )
    scan.add_argument(
        "--fail-fast",
        action="store_true",
        help="Abort on the first discovery or parsing error",
    )
    scan.add_argument(
        "--verbose",
        action="store_true",
        help="Increase diagnostic output",
    )
    scan.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce non-essential output",
    )

    subparsers.add_parser("version", help="Print the current CLI version")
    return parser


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        return launch_home_screen(interactive=sys.stdin.isatty() and sys.stdout.isatty())

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        from . import __version__

        print(__version__)
        return 0

    if args.command == "scan":
        cli_config = build_default_scan_config(args.path)
        cli_config.branch = args.branch
        cli_config.output_format = args.format
        cli_config.config_path = args.config
        cli_config.include_patterns = list(args.include)
        cli_config.exclude_patterns = list(args.exclude)
        cli_config.baseline_path = args.baseline
        cli_config.suppressions_path = args.suppressions
        cli_config.overrides_path = args.overrides
        cli_config.fail_on = args.fail_on
        cli_config.fail_on_explicit = args.fail_on is not None
        cli_config.max_noise = args.max_noise
        cli_config.fail_fast = args.fail_fast
        cli_config.verbose = args.verbose
        cli_config.quiet = args.quiet
        try:
            file_config = load_scan_config_file(args.config) if args.config else None
            config = merge_scan_config(cli_config, file_config)
        except ConfigError as exc:
            parser.error(str(exc))

        try:
            result = scan_repository(config)
            if config.output_format == "json":
                print(render_json(result))
            elif config.output_format == "sarif":
                print(render_sarif(result))
            else:
                print(render_text(result))
            if findings_exceed_threshold(result.findings, config.fail_on):
                return 1
            return 0
        except ValueError as exc:
            parser.error(str(exc))
        except Exception as exc:  # pragma: no cover - runtime safety net
            print(f"unexpected runtime failure: {exc}", file=sys.stderr)
            return 3

    parser.error(f"Unsupported command: {args.command}")
    return 2
