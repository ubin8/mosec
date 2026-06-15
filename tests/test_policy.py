from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path

from appsec_cli.cli import main
from appsec_cli.config import ScanConfig
from appsec_cli.findings import Confidence, Evidence, Finding, Severity, CodeLocation
from appsec_cli.policy import findings_exceed_threshold, policy_decision_for
from appsec_cli.scanner import scan_repository
from appsec_cli.reporting import render_sarif


def test_findings_exceed_threshold_detects_high_severity(tmp_path: Path) -> None:
    finding = Finding(
        id="finding-1",
        rule_id="RULE-1",
        title="Example",
        message="Example",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        location=CodeLocation(path=tmp_path / "a.py", start_line=1),
        category="example",
        evidence=Evidence(snippet="secret = 'value'"),
    )

    assert findings_exceed_threshold([finding], "high") is True
    assert findings_exceed_threshold([finding], "critical") is False
    assert policy_decision_for([finding], "high") == "blocked"
    assert policy_decision_for([finding], "critical") == "allowed"


def test_scan_command_returns_policy_violation_exit_code(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("API_KEY = 'abc123secretvalue'\n", encoding="utf-8")

    buffer = StringIO()
    with redirect_stdout(buffer):
        exit_code = main(["scan", str(tmp_path), "--fail-on", "high"])

    assert exit_code == 1


def test_scan_result_persists_policy_decision(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("API_KEY = 'abc123secretvalue'\n", encoding="utf-8")

    result = scan_repository(ScanConfig(root=tmp_path, fail_on="high"))

    assert result.policy_threshold == "high"
    assert result.policy_decision == "blocked"
    assert '"policy_decision": "blocked"' in result.to_json()
    assert '"policy_effective_threshold": "high"' in result.to_json()
    assert '"triage_status": "untriaged"' in result.to_json()
    assert '"audit_log"' in result.to_json()


def test_sarif_includes_policy_decision(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("API_KEY = 'abc123secretvalue'\n", encoding="utf-8")

    result = scan_repository(ScanConfig(root=tmp_path, fail_on="high"))
    sarif = json.loads(render_sarif(result))

    invocation = sarif["runs"][0]["invocations"][0]["properties"]
    assert invocation["policy_threshold"] == "high"
    assert invocation["policy_decision"] == "blocked"
    assert sarif["runs"][0]["results"][0]["properties"]["triage_status"] == "untriaged"
    assert sarif["runs"][0]["invocations"][0]["properties"]["audit_log"][0]["action"] == "policy"


def test_branch_specific_policy_overrides_default_threshold(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("API_KEY = 'abc123secretvalue'\n", encoding="utf-8")

    result = scan_repository(
        ScanConfig(
            root=tmp_path,
            branch="main",
            fail_on="high",
            branch_fail_on={"main": "critical"},
        )
    )

    assert result.policy_branch == "main"
    assert result.policy_threshold == "high"
    assert result.policy_effective_threshold == "critical"
    assert result.policy_decision == "allowed"


def test_explicit_fail_on_overrides_branch_specific_policy(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("API_KEY = 'abc123secretvalue'\n", encoding="utf-8")

    result = scan_repository(
        ScanConfig(
            root=tmp_path,
            branch="main",
            fail_on="high",
            fail_on_explicit=True,
            branch_fail_on={"main": "critical"},
        )
    )

    assert result.policy_branch == "main"
    assert result.policy_threshold == "high"
    assert result.policy_effective_threshold == "high"
    assert result.policy_decision == "blocked"
