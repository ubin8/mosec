from __future__ import annotations

from datetime import datetime, timezone

from .audit import AuditEntry
from .config import ScanConfig
from .detection import classify_files
from .detectors import run_detectors
from .ingestion import discover_files
from .models import ScanResult
from .policy import policy_decision_for, resolve_policy_threshold
from . import __version__
from .parsing import parse_files
from .rules import RulePack
from .workflow import (
    apply_baseline_and_suppressions,
    load_baseline_file,
    load_manual_overrides_file,
    load_suppressions_file,
)


BUILTIN_RULE_PACK = RulePack(name="builtin", version="0.1.0")


def scan_repository(config: ScanConfig) -> ScanResult:
    """Scan a repository using the current ingestion contract."""

    if config.root is None:
        raise ValueError("scan config must include a root path")

    started_at = datetime.now(timezone.utc).isoformat()
    discovery = discover_files(
        config.root,
        include_patterns=config.include_patterns,
        exclude_patterns=config.exclude_patterns,
        max_noise=config.max_noise,
        fail_fast=config.fail_fast,
    )
    result = ScanResult(root=discovery.root, started_at=started_at, tool_version=__version__)
    result.stats.files_seen = discovery.files_seen
    result.stats.files_selected = discovery.files_selected
    result.files = classify_files(discovery.selected_files)
    result.parsed_documents = parse_files(
        discovery.selected_files,
        result.files,
        parser_overrides=config.parser_overrides,
    )
    result.rule_packs = [BUILTIN_RULE_PACK]
    if config.max_noise:
        result.notes.append("max-noise mode enabled")
    all_findings = run_detectors(result.parsed_documents)
    baseline_entries = load_baseline_file(config.baseline_path)
    suppressions = load_suppressions_file(config.suppressions_path)
    manual_overrides = load_manual_overrides_file(config.overrides_path)
    filtered = apply_baseline_and_suppressions(
        all_findings,
        baseline_entries,
        suppressions,
        manual_overrides,
    )
    result.findings = filtered.active_findings
    result.baseline_findings = filtered.baselined_findings
    result.suppressed_findings = filtered.suppressed_findings
    result.audit_log = list(filtered.audit_entries)
    result.finalize()
    result.finished_at = datetime.now(timezone.utc).isoformat()
    result.policy_threshold = config.fail_on
    result.policy_branch = config.branch
    result.policy_effective_threshold = resolve_policy_threshold(
        config.fail_on,
        config.branch,
        config.branch_fail_on,
        config.fail_on_explicit,
    )
    result.policy_decision = policy_decision_for(result.findings, result.policy_effective_threshold)
    result.audit_log.append(
        AuditEntry(
            action="policy",
            subject_type="scan",
            subject_id=str(result.root),
            decision=result.policy_decision,
            reason=f"threshold={result.policy_effective_threshold or 'none'}",
            actor="scanner",
            created_at=result.finished_at,
            metadata={
                "policy_threshold": result.policy_threshold,
                "policy_effective_threshold": result.policy_effective_threshold,
                "branch": result.policy_branch,
            },
        )
    )
    result.notes.extend(discovery.notes)
    if not discovery.selected_files:
        result.notes.append("no files selected for analysis")
    else:
        languages = {}
        frameworks = {}
        for file in result.files:
            languages[file.language.value] = languages.get(file.language.value, 0) + 1
            if file.framework is not None:
                frameworks[file.framework.value] = frameworks.get(file.framework.value, 0) + 1
        if languages:
            language_summary = ", ".join(f"{name}={count}" for name, count in sorted(languages.items()))
            result.notes.append(f"languages detected: {language_summary}")
        if frameworks:
            framework_summary = ", ".join(f"{name}={count}" for name, count in sorted(frameworks.items()))
            result.notes.append(f"frameworks detected: {framework_summary}")
        parsed_valid = sum(1 for document in result.parsed_documents if document.syntax_valid)
        result.notes.append(
            f"parsed documents: {parsed_valid}/{len(result.parsed_documents)} syntax-valid"
        )
        if result.stats.baselined_findings:
            result.notes.append(f"baselined findings: {result.stats.baselined_findings}")
        if result.stats.suppressed_findings:
            result.notes.append(f"suppressed findings: {result.stats.suppressed_findings}")
        result.notes.append(f"findings produced: {len(result.findings)}")
        result.notes.append(
            f"{discovery.files_selected} file(s) selected for future analysis"
        )
    return result
