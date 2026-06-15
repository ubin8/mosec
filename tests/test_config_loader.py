from pathlib import Path

import pytest

from appsec_cli.config import (
    ConfigError,
    ScanConfig,
    build_default_scan_config,
    load_scan_config_file,
    merge_scan_config,
)


def test_build_default_scan_config_uses_current_working_directory() -> None:
    config = build_default_scan_config()

    assert config.root == Path.cwd()
    assert config.output_format == "text"
    assert config.include_patterns == []
    assert config.exclude_patterns == []
    assert config.fail_on is None
    assert config.verbose is False
    assert config.quiet is False


def test_load_scan_config_file_resolves_relative_paths() -> None:
    config = load_scan_config_file(Path("fixtures/config/appsec.toml"))

    assert config.output_format == "json"
    assert config.root is not None
    assert config.root.name == "fixtures"
    assert config.baseline_path is not None
    assert config.baseline_path.name == "baseline.json"
    assert config.suppressions_path is not None
    assert config.suppressions_path.name == "suppressions.json"
    assert config.overrides_path is not None
    assert config.overrides_path.name == "manual-overrides.json"
    assert config.include_patterns == ["src/**"]
    assert config.exclude_patterns == ["tests/**", "**/dist/**"]


def test_load_scan_config_file_reads_parser_overrides(tmp_path: Path) -> None:
    config_file = tmp_path / "mosec.toml"
    config_file.write_text(
        """
root = "."
format = "text"

[parsers]
python = "text"
javascript = "javascript"

[branch_fail_on]
main = "critical"
release = "high"
""".strip(),
        encoding="utf-8",
    )

    config = load_scan_config_file(config_file)

    assert config.parser_overrides == {"python": "text", "javascript": "javascript"}
    assert config.branch_fail_on == {"main": "critical", "release": "high"}


def test_load_scan_config_file_reads_max_noise_and_fail_fast(tmp_path: Path) -> None:
    config_file = tmp_path / "mosec.toml"
    config_file.write_text(
        """
root = "."
format = "text"
max_noise = true
fail_fast = true
""".strip(),
        encoding="utf-8",
    )

    config = load_scan_config_file(config_file)

    assert config.max_noise is True
    assert config.fail_fast is True


def test_merge_scan_config_prefers_cli_values() -> None:
    file_config = ScanConfig(
        root=Path("/repo"),
        output_format="json",
        include_patterns=["src/**"],
        exclude_patterns=["tests/**"],
        baseline_path=Path("/repo/baseline.json"),
        fail_on="high",
        branch="main",
        branch_fail_on={"main": "critical"},
    )
    cli_config = ScanConfig(
        root=Path("/override"),
        output_format="text",
        include_patterns=["app/**"],
        exclude_patterns=["generated/**"],
        fail_on="critical",
        verbose=True,
    )

    merged = merge_scan_config(cli_config, file_config)

    assert merged.root == Path("/override")
    assert merged.output_format == "text"
    assert merged.include_patterns == ["src/**", "app/**"]
    assert merged.exclude_patterns == ["tests/**", "generated/**"]
    assert merged.baseline_path == Path("/repo/baseline.json")
    assert merged.fail_on == "critical"
    assert merged.branch == "main"
    assert merged.branch_fail_on == {"main": "critical"}
    assert merged.verbose is True
    assert merged.quiet is False


def test_merge_scan_config_rejects_verbose_and_quiet() -> None:
    with pytest.raises(ConfigError):
        merge_scan_config(
            ScanConfig(root=Path("/repo"), verbose=True),
            ScanConfig(root=Path("/repo"), quiet=True),
        )
