from pathlib import Path
import json

import pytest

from appsec_cli.config import ScanConfig
from appsec_cli.findings import TriageStatus
from appsec_cli.scanner import scan_repository
from appsec_cli.workflow import load_suppressions_file


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_baseline_filters_known_secret_fixture() -> None:
    result = scan_repository(
        ScanConfig(
            root=_repo_root(),
            include_patterns=["fixtures/secrets/python/hardcoded_secret.py"],
            baseline_path=_repo_root() / "fixtures" / "baseline" / "baseline.json",
        )
    )

    assert result.stats.findings == 0
    assert result.stats.baselined_findings == 1
    assert result.findings == []
    assert any("baselined findings: 1" in note for note in result.notes)
    assert result.baseline_findings[0].triage_status == TriageStatus.UNTRIAGED
    assert result.audit_log[0].action == "baseline"
    assert result.audit_log[0].decision == "baselined"


def test_suppression_filters_known_sql_fixture() -> None:
    result = scan_repository(
        ScanConfig(
            root=_repo_root(),
            include_patterns=["fixtures/web/python/raw_sql.py"],
            suppressions_path=_repo_root() / "fixtures" / "suppressions" / "suppressions.json",
        )
    )

    assert result.stats.findings == 0
    assert result.stats.suppressed_findings == 1
    assert result.findings == []
    assert any("suppressed findings: 1" in note for note in result.notes)
    assert result.suppressed_findings[0].triage_status == TriageStatus.UNTRIAGED
    assert result.audit_log[0].action == "suppression"
    assert result.audit_log[0].decision == "suppressed"
    assert result.audit_log[0].metadata["review_status"] == "approved"
    assert result.audit_log[0].metadata["reviewed_by"] == "security-reviewer"


def test_expired_suppression_is_ignored(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "def run_query(user_input, db):\n"
        "    query = \"SELECT * FROM users WHERE name = '\" + user_input + \"'\"\n"
        "    return db.execute(query)\n",
        encoding="utf-8",
    )

    suppressions = tmp_path / "suppressions.json"
    suppressions.write_text(
        json.dumps(
            {
                "suppressions": [
                    {
                        "target": {
                            "rule_id": "WEB-SQLI-001",
                            "path": "app.py",
                            "start_line": 2,
                        },
                        "reason": "temporary exception",
                        "created_at": "2026-06-14T00:00:00Z",
                        "expires_at": "2020-01-01T00:00:00Z",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = scan_repository(
        ScanConfig(root=tmp_path, suppressions_path=suppressions)
    )

    assert result.stats.findings >= 1
    assert result.stats.suppressed_findings == 0
    assert any(f.rule_id == "WEB-SQLI-001" for f in result.findings)


def test_pending_suppression_does_not_match(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "def run_query(user_input, db):\n"
        "    query = \"SELECT * FROM users WHERE name = '\" + user_input + \"'\"\n"
        "    return db.execute(query)\n",
        encoding="utf-8",
    )

    suppressions = tmp_path / "suppressions.json"
    suppressions.write_text(
        json.dumps(
            {
                "suppressions": [
                    {
                        "target": {
                            "rule_id": "WEB-SQLI-001",
                            "path": "app.py",
                            "start_line": 2,
                        },
                        "reason": "pending review",
                        "review_status": "pending",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = scan_repository(ScanConfig(root=tmp_path, suppressions_path=suppressions))

    assert result.stats.findings >= 1
    assert result.stats.suppressed_findings == 0
    assert any(f.rule_id == "WEB-SQLI-001" for f in result.findings)


def test_rejected_suppression_does_not_match(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text(
        "def run_query(user_input, db):\n"
        "    query = \"SELECT * FROM users WHERE name = '\" + user_input + \"'\"\n"
        "    return db.execute(query)\n",
        encoding="utf-8",
    )

    suppressions = tmp_path / "suppressions.json"
    suppressions.write_text(
        json.dumps(
            {
                "suppressions": [
                    {
                        "target": {
                            "rule_id": "WEB-SQLI-001",
                            "path": "app.py",
                            "start_line": 2,
                        },
                        "reason": "rejected in review",
                        "review_status": "rejected",
                        "reviewed_by": "security-lead",
                        "review_note": "insufficient justification",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = scan_repository(ScanConfig(root=tmp_path, suppressions_path=suppressions))

    assert result.stats.findings >= 1
    assert result.stats.suppressed_findings == 0
    assert any(f.rule_id == "WEB-SQLI-001" for f in result.findings)


def test_suppression_file_requires_reason(tmp_path: Path) -> None:
    suppressions = tmp_path / "suppressions.json"
    suppressions.write_text(
        '{"suppressions": [{"target": {"rule_id": "WEB-SQLI-001", "path": "app.py", "start_line": 1}}]}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_suppressions_file(suppressions)


def test_suppression_file_rejects_invalid_review_status(tmp_path: Path) -> None:
    suppressions = tmp_path / "suppressions.json"
    suppressions.write_text(
        json.dumps(
            {
                "suppressions": [
                    {
                        "target": {
                            "rule_id": "WEB-SQLI-001",
                            "path": "app.py",
                            "start_line": 1,
                        },
                        "reason": "invalid review state",
                        "review_status": "unknown",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_suppressions_file(suppressions)
