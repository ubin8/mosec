from pathlib import Path

import pytest

from mosec.findings import Confidence, Severity
from mosec.rule_loader import RulePackError, load_rule_pack
from mosec.rules import MatchStrategy, RuleCategory


def test_load_rule_pack_from_toml_fixture() -> None:
    pack = load_rule_pack(Path("fixtures/rules/builtin.toml"))

    assert pack.name == "builtin"
    assert pack.version == "0.1.0"
    assert len(pack.rules) == 1
    assert pack.rules[0].category == RuleCategory.SECRETS
    assert pack.rules[0].severity == Severity.HIGH
    assert pack.rules[0].confidence == Confidence.MEDIUM
    assert pack.rules[0].strategy == MatchStrategy.PATTERN
    assert pack.rules[0].targets[0].language == "python"
    assert pack.rules[0].patterns[0].kind == "regex"


def test_rule_pack_fixture_matches_schema() -> None:
    pack = load_rule_pack(Path("fixtures/rules/builtin.toml"))

    payload = pack.to_dict()

    assert payload["name"] == "builtin"
    assert payload["rules"][0]["remediation"] == "Move secrets out of source control."


def test_load_rule_pack_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(RulePackError):
        load_rule_pack(tmp_path / "missing.toml")
