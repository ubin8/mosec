import json
from pathlib import Path

from appsec_cli.audit import AuditEntry
from appsec_cli.models import ScanResult
from appsec_cli.reporting import render_json, render_sarif, render_text

def test_json_report_matches_golden_fixture() -> None:
    result = ScanResult(root=Path("fixtures/secrets/python"))

    payload = json.loads(render_json(result))
    golden = json.loads((_repo_root() / "fixtures" / "reports" / "json" / "golden.json").read_text(encoding="utf-8"))

    assert payload == golden


def test_sarif_report_matches_golden_fixture() -> None:
    result = ScanResult(root=Path("fixtures/secrets/python"))

    payload = json.loads(render_sarif(result))
    golden = json.loads((_repo_root() / "fixtures" / "reports" / "sarif" / "golden.sarif").read_text(encoding="utf-8"))

    assert payload == golden


def test_text_report_contains_summary() -> None:
    result = ScanResult(root=Path("fixtures/secrets/python"))

    text = render_text(result)

    assert "scan root:" in text
    assert "findings:" in text


def test_report_includes_audit_log_entries() -> None:
    result = ScanResult(
        root=Path("fixtures/secrets/python"),
        audit_log=[
            AuditEntry(
                action="policy",
                subject_type="scan",
                subject_id="fixtures/secrets/python",
                decision="blocked",
                reason="threshold=high",
                actor="scanner",
            )
        ],
    )

    json_payload = json.loads(render_json(result))
    sarif_payload = json.loads(render_sarif(result))
    text = render_text(result)

    assert json_payload["audit_log"][0]["action"] == "policy"
    assert sarif_payload["runs"][0]["invocations"][0]["properties"]["audit_log"][0]["decision"] == "blocked"
    assert "audit log:" in text
