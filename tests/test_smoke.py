from pathlib import Path

from appsec_cli.config import ScanConfig
from appsec_cli.audit import AuditEntry
from appsec_cli.detection import Framework, Language
from appsec_cli.findings import (
    CodeLocation,
    CodeSymbolReference,
    Confidence,
    Evidence,
    Finding,
    Severity,
    TriageStatus,
)
from appsec_cli.rules import MatchStrategy, Rule, RuleCategory, RulePattern, RuleTarget, RulePack
from appsec_cli.models import ScanResult
from appsec_cli.scanner import scan_repository
from appsec_cli.workflow import apply_baseline_and_suppressions, BaselineEntry, Suppression, SuppressionTarget


def test_scan_repository_returns_result(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "from flask import Flask\nAPI_KEY = 'abc123secretvalue'\nquery = \"SELECT * FROM users WHERE name = '\" + user_input + \"'\"\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "package.json").write_text(
        '{"dependencies": {"express": "4.18.2", "lodash": "4.17.21"}}',
        encoding="utf-8",
    )
    (tmp_path / "src" / "empty.py").write_text("", encoding="utf-8")
    (tmp_path / "src" / "binary.bin").write_bytes(b"\x00\x01\x02")

    result = scan_repository(
        ScanConfig(
            root=tmp_path,
            include_patterns=["src/**"],
            exclude_patterns=["**/empty.py"],
        )
    )

    assert result.root == tmp_path.resolve()
    assert result.stats.files_seen == 4
    assert result.stats.files_selected == 1
    assert result.stats.findings == 4
    assert any(f.rule_id == "SEC-SECRET-001" for f in result.findings)
    assert any(f.rule_id == "WEB-SQLI-001" for f in result.findings)
    assert any(f.rule_id == "SCA-PACKAGE-001" for f in result.findings)
    assert result.rule_packs[0].name == "builtin"
    assert result.rule_packs[0].version == "0.1.0"
    assert result.started_at is not None
    assert result.finished_at is not None
    assert result.tool_version == "0.1.0"
    assert "started at:" in result.to_text()
    assert "rule packs:" in result.to_text()
    secret_finding = next(f for f in result.findings if f.rule_id == "SEC-SECRET-001")
    assert secret_finding.location.path.name == "app.py"
    assert secret_finding.location.start_line == 2
    assert result.files[0].language == Language.PYTHON
    assert result.parsed_documents[0].syntax_valid is True
    assert any("findings produced" in note for note in result.notes)


def test_rule_and_finding_serialization(tmp_path: Path) -> None:
    rule = Rule(
        id="SEC-SECRET-001",
        name="Hardcoded Secret",
        description="Detects obvious hardcoded secret material.",
        category=RuleCategory.SECRETS,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        strategy=MatchStrategy.PATTERN,
        targets=[RuleTarget(language="python")],
        owasp=["A05:2021 - Security Misconfiguration"],
        cwe=["CWE-798"],
        patterns=[RulePattern(kind="regex", value=r"secret\s*=")],
        remediation="Move the secret out of the source tree.",
        examples=["secret = 'abc'"],
    )
    finding = Finding(
        id="finding-1",
        rule_id=rule.id,
        title=rule.name,
        message=rule.description,
        severity=rule.severity,
        confidence=rule.confidence,
        location=CodeLocation(path=tmp_path / "app.py", start_line=3),
        category=rule.category.value,
        language="python",
        owasp=list(rule.owasp),
        cwe=list(rule.cwe),
        evidence=Evidence(snippet="secret = 'abc'", start_line=3, end_line=3),
        remediation=rule.remediation,
        triage_status=TriageStatus.IN_REVIEW,
        triage_reason="accepted as test data",
        triage_note="reviewed in smoke test",
        symbols=[CodeSymbolReference(name="secret", kind="assignment", qualified_name="app.secret", line=3)],
    )
    pack = RulePack(name="builtin", version="0.1.0", rules=[rule])

    assert rule.to_dict()["category"] == "secrets"
    assert finding.to_dict()["severity"] == "high"
    assert finding.to_dict()["triage_status"] == "in_review"
    assert finding.to_dict()["triage_reason"] == "accepted as test data"
    assert finding.to_dict()["triage_note"] == "reviewed in smoke test"
    assert finding.to_summary().startswith("HIGH Hardcoded Secret")
    assert finding.to_dict()["symbols"][0]["name"] == "secret"
    assert pack.to_dict()["rules"][0]["id"] == "SEC-SECRET-001"


def test_triage_reason_survives_baseline_and_suppression_cloning(tmp_path: Path) -> None:
    finding = Finding(
        id="finding-1",
        rule_id="WEB-SQLI-001",
        title="Example",
        message="Example",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        location=CodeLocation(path=tmp_path / "app.py", start_line=1),
        category="injection",
        triage_reason="reviewed manually",
        triage_note="baseline test",
    )

    baseline_result = apply_baseline_and_suppressions(
        [finding],
        baseline_entries=[BaselineEntry(rule_id="WEB-SQLI-001", path="app.py", start_line=1, reason="legacy finding")],
    )
    suppressed_result = apply_baseline_and_suppressions(
        [finding],
        suppressions=[Suppression(target=SuppressionTarget(rule_id="WEB-SQLI-001", path="app.py", start_line=1), reason="accepted risk")],
    )

    assert baseline_result.baselined_findings[0].triage_reason == "reviewed manually"
    assert baseline_result.baselined_findings[0].triage_note == "baseline test"
    assert suppressed_result.suppressed_findings[0].triage_reason == "reviewed manually"
    assert suppressed_result.suppressed_findings[0].triage_note == "baseline test"


def test_audit_entry_serializes_cleanly() -> None:
    entry = AuditEntry(
        action="policy",
        subject_type="scan",
        subject_id="root",
        decision="allowed",
        reason="threshold=high",
        actor="scanner",
    )

    payload = entry.to_dict()

    assert payload["action"] == "policy"
    assert payload["decision"] == "allowed"


def test_scan_result_counts_findings_automatically(tmp_path: Path) -> None:
    finding = Finding(
        id="finding-1",
        rule_id="RULE-1",
        title="Example",
        message="Example message",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        location=CodeLocation(path=tmp_path / "a.py", start_line=1),
        category="example",
    )

    result = ScanResult(root=tmp_path, findings=[finding])

    assert result.stats.findings == 1


def test_scan_result_prioritizes_reachable_findings(tmp_path: Path) -> None:
    reachable = Finding(
        id="finding-reachable",
        rule_id="RULE-1",
        title="Reachable",
        message="Reachable",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=CodeLocation(path=tmp_path / "a.py", start_line=2),
        category="example",
        metadata={"taint_reachability": "reachable"},
    )
    unreachable = Finding(
        id="finding-unreachable",
        rule_id="RULE-1",
        title="Unreachable",
        message="Unreachable",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        location=CodeLocation(path=tmp_path / "a.py", start_line=1),
        category="example",
        metadata={"taint_reachability": "unreachable"},
    )

    result = ScanResult(root=tmp_path, findings=[unreachable, reachable])

    assert result.findings[0].id == "finding-reachable"
    assert result.findings[1].id == "finding-unreachable"


def test_scan_result_serializes_parsed_documents(tmp_path: Path) -> None:
    from appsec_cli.parsing import ParsedDocument

    document = ParsedDocument(
        path=tmp_path / "a.py",
        relative_path="a.py",
        language=Language.PYTHON,
        framework=Framework.FLASK.value,
        syntax_valid=True,
        line_count=1,
        character_count=10,
    )
    result = ScanResult(root=tmp_path, parsed_documents=[document])

    payload = result.to_json()

    assert '"parsed_documents"' in payload
