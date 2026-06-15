from pathlib import Path
import json

import pytest

from mosec.config import ScanConfig
from mosec.scanner import scan_repository
from mosec.workflow import load_manual_overrides_file


def test_manual_override_fixture_loads() -> None:
    overrides = load_manual_overrides_file(Path("fixtures/overrides/manual-overrides.json"))

    assert len(overrides) == 1
    assert overrides[0].decision.value == "active"
    assert overrides[0].reason == "manually approved to remain visible for review"


def test_manual_override_active_keeps_finding_visible(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "def run_query(user_input, db):\n"
        "    query = \"SELECT * FROM users WHERE name = '\" + user_input + \"'\"\n"
        "    return db.execute(query)\n",
        encoding="utf-8",
    )

    suppression_file = tmp_path / "suppressions.json"
    suppression_file.write_text(
        json.dumps(
            {
                "suppressions": [
                    {
                        "target": {
                            "rule_id": "WEB-SQLI-001",
                            "path": "app.py",
                            "start_line": 2,
                        },
                        "reason": "existing suppression",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    overrides_file = tmp_path / "overrides.json"
    overrides_file.write_text(
        json.dumps(
            {
                "overrides": [
                    {
                        "target": {
                            "rule_id": "WEB-SQLI-001",
                            "path": "app.py",
                            "start_line": 2,
                        },
                        "decision": "active",
                        "reason": "manual review keeps it visible",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = scan_repository(
        ScanConfig(root=tmp_path, suppressions_path=suppression_file, overrides_path=overrides_file)
    )

    assert any(f.rule_id == "WEB-SQLI-001" for f in result.findings)
    assert result.stats.suppressed_findings == 0
    assert result.audit_log[0].action == "manual_override"
    assert result.audit_log[0].decision == "active"
    assert result.findings[0].metadata["manual_override_decision"] == "active"


def test_manual_override_suppressed_hides_finding(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "def run_query(user_input, db):\n"
        "    query = \"SELECT * FROM users WHERE name = '\" + user_input + \"'\"\n"
        "    return db.execute(query)\n",
        encoding="utf-8",
    )

    overrides_file = tmp_path / "overrides.json"
    overrides_file.write_text(
        json.dumps(
            {
                "overrides": [
                    {
                        "target": {
                            "rule_id": "WEB-SQLI-001",
                            "path": "app.py",
                            "start_line": 2,
                        },
                        "decision": "suppressed",
                        "reason": "manually accepted risk",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = scan_repository(ScanConfig(root=tmp_path, overrides_path=overrides_file))

    assert result.stats.findings == 0
    assert result.stats.suppressed_findings == 1
    assert result.suppressed_findings[0].metadata["manual_override_decision"] == "suppressed"
    assert result.audit_log[0].action == "manual_override"
    assert result.audit_log[0].decision == "suppressed"


def test_manual_override_file_rejects_invalid_decision(tmp_path: Path) -> None:
    overrides = tmp_path / "overrides.json"
    overrides.write_text(
        json.dumps(
            {
                "overrides": [
                    {
                        "target": {
                            "rule_id": "WEB-SQLI-001",
                            "path": "app.py",
                            "start_line": 1,
                        },
                        "decision": "unknown",
                        "reason": "invalid",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_manual_overrides_file(overrides)
