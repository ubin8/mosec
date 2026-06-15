from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    pass


@dataclass(slots=True)
class ScanConfig:
    """Configuration for a repository scan."""

    root: Path | None = None
    branch: str | None = None
    output_format: str | None = None
    config_path: Path | None = None
    include_patterns: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)
    baseline_path: Path | None = None
    suppressions_path: Path | None = None
    overrides_path: Path | None = None
    parser_overrides: dict[str, str] = field(default_factory=dict)
    branch_fail_on: dict[str, str] = field(default_factory=dict)
    max_noise: bool = False
    fail_fast: bool = False
    fail_on: str | None = None
    fail_on_explicit: bool = False
    verbose: bool = False
    quiet: bool = False


def build_default_scan_config(root: Path | None = None) -> ScanConfig:
    """Build the implicit scan configuration used when no config file is present."""

    return ScanConfig(
        root=root or Path.cwd(),
        branch=None,
        output_format="text",
        include_patterns=[],
        exclude_patterns=[],
        baseline_path=None,
        suppressions_path=None,
        overrides_path=None,
        branch_fail_on={},
        fail_on=None,
        fail_on_explicit=False,
        verbose=False,
        quiet=False,
    )


def _require_string_list(value: Any, field_name: str) -> list[str]:
    if not isinstance(value, list):
        raise ConfigError(f"field '{field_name}' must be a list")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ConfigError(f"field '{field_name}' must contain only non-empty strings")
        result.append(item)
    return result


def load_scan_config_file(path: Path) -> ScanConfig:
    resolved = path.expanduser().resolve()
    if not resolved.exists():
        raise ConfigError(f"config file does not exist: {resolved}")
    if resolved.is_dir():
        raise ConfigError(f"config path must be a file: {resolved}")

    try:
        import tomllib
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise ConfigError("TOML parsing support is unavailable") from exc

    parsed = tomllib.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ConfigError("config root must be a table")

    allowed_keys = {
        "root",
        "branch_fail_on",
        "format",
        "include",
        "exclude",
        "baseline",
        "suppressions",
        "overrides",
        "parsers",
        "max_noise",
        "fail_fast",
        "fail_on",
        "verbose",
        "quiet",
    }
    unknown_keys = sorted(set(parsed) - allowed_keys)
    if unknown_keys:
        raise ConfigError(f"unknown config keys: {', '.join(unknown_keys)}")

    root_value = parsed.get("root")
    if root_value is not None and (not isinstance(root_value, str) or not root_value.strip()):
        raise ConfigError("field 'root' must be a non-empty string when provided")

    format_value = parsed.get("format", "text")
    if not isinstance(format_value, str) or format_value not in {"text", "json", "sarif"}:
        raise ConfigError("field 'format' must be one of: text, json, sarif")

    include_patterns = _require_string_list(parsed.get("include", []), "include")
    exclude_patterns = _require_string_list(parsed.get("exclude", []), "exclude")

    baseline_value = parsed.get("baseline")
    if baseline_value is not None and (not isinstance(baseline_value, str) or not baseline_value.strip()):
        raise ConfigError("field 'baseline' must be a non-empty string when provided")

    suppressions_value = parsed.get("suppressions")
    if suppressions_value is not None and (not isinstance(suppressions_value, str) or not suppressions_value.strip()):
        raise ConfigError("field 'suppressions' must be a non-empty string when provided")

    overrides_value = parsed.get("overrides")
    if overrides_value is not None and (not isinstance(overrides_value, str) or not overrides_value.strip()):
        raise ConfigError("field 'overrides' must be a non-empty string when provided")

    parser_overrides_value = parsed.get("parsers", {})
    if not isinstance(parser_overrides_value, dict):
        raise ConfigError("field 'parsers' must be a table")
    parser_overrides: dict[str, str] = {}
    valid_parsers = {"python", "javascript", "typescript", "json", "toml", "xml", "text"}
    for key, value in parser_overrides_value.items():
        if not isinstance(key, str) or not key.strip():
            raise ConfigError("field 'parsers' must use non-empty string keys")
        if not isinstance(value, str) or value not in valid_parsers:
            raise ConfigError(
                "field 'parsers' values must be one of: python, javascript, typescript, json, toml, xml, text"
            )
        parser_overrides[key.strip()] = value

    branch_fail_on_value = parsed.get("branch_fail_on", {})
    if not isinstance(branch_fail_on_value, dict):
        raise ConfigError("field 'branch_fail_on' must be a table")
    branch_fail_on: dict[str, str] = {}
    for key, value in branch_fail_on_value.items():
        if not isinstance(key, str) or not key.strip():
            raise ConfigError("field 'branch_fail_on' must use non-empty string keys")
        if value not in {"low", "medium", "high", "critical"}:
            raise ConfigError("field 'branch_fail_on' values must be one of: low, medium, high, critical")
        branch_fail_on[key.strip()] = value

    fail_on_value = parsed.get("fail_on")
    if fail_on_value is not None and fail_on_value not in {"low", "medium", "high", "critical"}:
        raise ConfigError("field 'fail_on' must be one of: low, medium, high, critical")

    max_noise_value = parsed.get("max_noise", False)
    fail_fast_value = parsed.get("fail_fast", False)
    if not isinstance(max_noise_value, bool):
        raise ConfigError("field 'max_noise' must be a boolean")
    if not isinstance(fail_fast_value, bool):
        raise ConfigError("field 'fail_fast' must be a boolean")

    verbose_value = parsed.get("verbose", False)
    quiet_value = parsed.get("quiet", False)
    if not isinstance(verbose_value, bool):
        raise ConfigError("field 'verbose' must be a boolean")
    if not isinstance(quiet_value, bool):
        raise ConfigError("field 'quiet' must be a boolean")

    def _resolve_config_path(raw_value: str | None) -> Path | None:
        if raw_value is None:
            return None
        candidate = Path(raw_value).expanduser()
        if not candidate.is_absolute():
            candidate = (resolved.parent / candidate).resolve()
        return candidate

    return ScanConfig(
        root=_resolve_config_path(root_value),
        branch=None,
        output_format=format_value,
        config_path=resolved,
        include_patterns=include_patterns,
        exclude_patterns=exclude_patterns,
        baseline_path=_resolve_config_path(baseline_value),
        suppressions_path=_resolve_config_path(suppressions_value),
        overrides_path=_resolve_config_path(overrides_value),
        parser_overrides=parser_overrides,
        branch_fail_on=branch_fail_on,
        max_noise=max_noise_value,
        fail_fast=fail_fast_value,
        fail_on=fail_on_value,
        fail_on_explicit=False,
        verbose=verbose_value,
        quiet=quiet_value,
    )


def merge_scan_config(
    cli_config: ScanConfig,
    file_config: ScanConfig | None = None,
) -> ScanConfig:
    file_config = file_config or ScanConfig()

    include_patterns = list(file_config.include_patterns)
    for pattern in cli_config.include_patterns:
        if pattern not in include_patterns:
            include_patterns.append(pattern)

    exclude_patterns = list(file_config.exclude_patterns)
    for pattern in cli_config.exclude_patterns:
        if pattern not in exclude_patterns:
            exclude_patterns.append(pattern)

    parser_overrides = dict(file_config.parser_overrides)
    parser_overrides.update(cli_config.parser_overrides)

    branch_fail_on = dict(file_config.branch_fail_on)
    branch_fail_on.update(cli_config.branch_fail_on)

    merged = ScanConfig(
        root=cli_config.root or file_config.root,
        branch=cli_config.branch or file_config.branch,
        output_format=cli_config.output_format or file_config.output_format or "text",
        config_path=cli_config.config_path or file_config.config_path,
        include_patterns=include_patterns,
        exclude_patterns=exclude_patterns,
        baseline_path=cli_config.baseline_path or file_config.baseline_path,
        suppressions_path=cli_config.suppressions_path or file_config.suppressions_path,
        overrides_path=cli_config.overrides_path or file_config.overrides_path,
        parser_overrides=parser_overrides,
        branch_fail_on=branch_fail_on,
        max_noise=cli_config.max_noise or file_config.max_noise,
        fail_fast=cli_config.fail_fast or file_config.fail_fast,
        fail_on=cli_config.fail_on or file_config.fail_on,
        fail_on_explicit=cli_config.fail_on_explicit or file_config.fail_on_explicit,
        verbose=cli_config.verbose or file_config.verbose,
        quiet=cli_config.quiet or file_config.quiet,
    )

    if merged.verbose and merged.quiet:
        raise ConfigError("verbose and quiet cannot both be enabled")

    return merged
