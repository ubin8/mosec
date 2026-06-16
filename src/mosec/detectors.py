from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .detection import FileClassification, Framework, Language
from .findings import CodeLocation, Confidence, Evidence, Finding, FindingStatus, Severity
from .models import ScanResult
from .parsing import ParsedDocument
from .sca import AdvisoryMatch, DependencyRecord, DependencyScope, LocalAdvisoryBackend, VulnerabilityBackend
from .rules import RuleCategory
from .taint import TaintState, build_assignment_taint_state, is_string_escape_sanitized_expression, is_url_allowlist_guard_expression, line_uses_tainted_flow, taint_propagation_metadata
from .sources import SourceKind, is_auth_context_reference, is_auth_guard_reference, is_body_source_reference, is_cookie_source_reference, is_header_source_reference, is_query_source_reference, is_role_guard_reference


@dataclass(slots=True, frozen=True)
class DetectorFindingTemplate:
    rule_id: str
    title: str
    message: str
    severity: Severity
    confidence: Confidence
    category: RuleCategory
    owasp: list[str]
    cwe: list[str]
    remediation: str
    tags: list[str]


SECRET_RULE = DetectorFindingTemplate(
    rule_id="SEC-SECRET-001",
    title="Hardcoded Secret",
    message="Hardcoded secret material detected in source code.",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    category=RuleCategory.SECRETS,
    owasp=["A02:2021 - Cryptographic Failures", "A05:2021 - Security Misconfiguration"],
    cwe=["CWE-798", "CWE-259"],
    remediation="Move secrets to a secret manager or environment variables and rotate exposed values.",
    tags=["secrets", "hardcoded", "credential"],
)

SQLI_RULE = DetectorFindingTemplate(
    rule_id="WEB-SQLI-001",
    title="Unsanitized SQL Query",
    message="A string looks like it is being passed directly into a SQL execution sink.",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    category=RuleCategory.INJECTION,
    owasp=["A03:2021 - Injection"],
    cwe=["CWE-89"],
    remediation="Use parameterized queries or ORM bind parameters.",
    tags=["web", "sql", "injection"],
)

DESERIALIZATION_RULE = DetectorFindingTemplate(
    rule_id="WEB-DESERIAL-001",
    title="Potential Unsafe Deserialization",
    message="A user-controlled value appears to reach a deserialization sink.",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    category=RuleCategory.DESERIALIZATION,
    owasp=["A08:2021 - Software and Data Integrity Failures"],
    cwe=["CWE-502"],
    remediation="Avoid native object deserialization from untrusted data and prefer typed, validated formats.",
    tags=["web", "deserialization", "java"],
)

ORM_RULE = DetectorFindingTemplate(
    rule_id="WEB-ORM-001",
    title="Potential Unsafe ORM Query",
    message="A user-controlled value appears to flow into a raw ORM query sink.",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    category=RuleCategory.INJECTION,
    owasp=["A03:2021 - Injection"],
    cwe=["CWE-89"],
    remediation="Use ORM parameter binding or safe query builders and avoid raw SQL fragments.",
    tags=["web", "orm", "sql", "python"],
)

XSS_RULE = DetectorFindingTemplate(
    rule_id="WEB-XSS-001",
    title="DOM XSS Sink",
    message="User-controlled content appears to flow into a browser HTML sink.",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    category=RuleCategory.XSS,
    owasp=["A03:2021 - Injection"],
    cwe=["CWE-79"],
    remediation="Use safe DOM APIs such as textContent or framework escaping helpers.",
    tags=["web", "xss", "dom"],
)

SSRF_RULE = DetectorFindingTemplate(
    rule_id="WEB-SSRF-001",
    title="Potential SSRF Sink",
    message="A user-controlled value appears to reach a network-request sink.",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    category=RuleCategory.SSRF,
    owasp=["A10:2021 - Server-Side Request Forgery (SSRF)"],
    cwe=["CWE-918"],
    remediation="Validate and allowlist destination URLs before making outbound requests.",
    tags=["web", "ssrf", "request"],
)

PATH_TRAVERSAL_RULE = DetectorFindingTemplate(
    rule_id="WEB-PATH-001",
    title="Potential Path Traversal",
    message="A user-controlled value appears to reach a file-system path sink.",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    category=RuleCategory.PATH_TRAVERSAL,
    owasp=["A01:2021 - Broken Access Control"],
    cwe=["CWE-22"],
    remediation="Normalize paths and constrain file access to an allowlisted base directory.",
    tags=["web", "path", "traversal"],
)

FILE_ACCESS_RULE = DetectorFindingTemplate(
    rule_id="WEB-FILE-001",
    title="Potential Unsafe File Access",
    message="A user-controlled value appears to reach a file-access sink.",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    category=RuleCategory.FILE_ACCESS,
    owasp=["A01:2021 - Broken Access Control"],
    cwe=["CWE-22", "CWE-73"],
    remediation="Restrict file access to allowlisted paths and validate user input before opening files.",
    tags=["web", "file", "filesystem"],
)

PROCESS_RULE = DetectorFindingTemplate(
    rule_id="WEB-PROC-001",
    title="Potential Unsafe Process Execution",
    message="A user-controlled value appears to reach a process execution sink.",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    category=RuleCategory.PROCESS_EXECUTION,
    owasp=["A03:2021 - Injection"],
    cwe=["CWE-78"],
    remediation="Avoid shell execution with user input and use safe process APIs with fixed arguments.",
    tags=["web", "process", "command", "php"],
)

ANDROID_ACTIVITY_RULE = DetectorFindingTemplate(
    rule_id="MOBILE-ANDROID-001",
    title="Exported Android Activity",
    message="An exported Android activity can be launched by other apps.",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    category=RuleCategory.MOBILE,
    owasp=["A01:2021 - Broken Access Control"],
    cwe=["CWE-926"],
    remediation="Restrict exported activities or protect them with permissions and explicit validation.",
    tags=["mobile", "android", "manifest", "activity"],
)

ANDROID_RECEIVER_RULE = DetectorFindingTemplate(
    rule_id="MOBILE-ANDROID-002",
    title="Exported Android Broadcast Receiver",
    message="An exported Android broadcast receiver can be triggered by other apps.",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    category=RuleCategory.MOBILE,
    owasp=["A01:2021 - Broken Access Control"],
    cwe=["CWE-926"],
    remediation="Restrict exported receivers or protect them with permissions and explicit validation.",
    tags=["mobile", "android", "manifest", "receiver"],
)

ANDROID_DANGEROUS_PERMISSION_RULE = DetectorFindingTemplate(
    rule_id="MOBILE-ANDROID-003",
    title="Dangerous Android Permission",
    message="The app requests a dangerous Android permission.",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    category=RuleCategory.MOBILE,
    owasp=["A05:2021 - Security Misconfiguration", "A01:2021 - Broken Access Control"],
    cwe=["CWE-250", "CWE-284"],
    remediation="Request only the permissions the app truly needs and explain why each dangerous permission is required.",
    tags=["mobile", "android", "manifest", "permission"],
)

ANDROID_SHARED_PREFERENCES_RULE = DetectorFindingTemplate(
    rule_id="MOBILE-ANDROID-004",
    title="Insecure SharedPreferences Usage",
    message="SharedPreferences appears to be used to store sensitive data without strong protection.",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    category=RuleCategory.MOBILE,
    owasp=["A02:2021 - Cryptographic Failures", "A05:2021 - Security Misconfiguration"],
    cwe=["CWE-312", "CWE-276"],
    remediation="Avoid storing secrets in plain SharedPreferences and prefer encrypted storage for sensitive values.",
    tags=["mobile", "android", "sharedpreferences", "storage"],
)


_ANDROID_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.BODY_SENSORS_BACKGROUND",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_ADVERTISE",
}

_ANDROID_SHARED_PREFERENCES_SECRET_KEYS = (
    "token",
    "secret",
    "password",
    "passwd",
    "passphrase",
    "api_key",
    "apikey",
    "auth",
    "session",
    "jwt",
    "credential",
    "refresh",
)


def _looks_like_android_shared_preferences(line: str, window: str) -> dict[str, Any] | None:
    lowered = line.lower()
    window_lower = window.lower()

    android_marker = any(
        marker in window_lower
        for marker in (
            "sharedpreferences",
            "getsharedpreferences(",
            "android.content.sharedpreferences",
            "encryptedsharedpreferences",
        )
    )
    if not android_marker or "encryptedsharedpreferences" in window_lower:
        return None

    if any(marker in lowered for marker in ("mode_world_readable", "mode_world_writeable")):
        return {
            "storage_kind": "shared_preferences",
            "storage_risk": "world_accessible_mode",
            "shared_preferences_mode": (
                "world_readable" if "mode_world_readable" in lowered else "world_writeable"
            ),
        }

    if "putstring(" in lowered or "putcharsequence(" in lowered:
        if any(secret in lowered for secret in _ANDROID_SHARED_PREFERENCES_SECRET_KEYS):
            return {
                "storage_kind": "shared_preferences",
                "storage_risk": "sensitive_value_in_plaintext",
                "shared_preferences_key": _extract_shared_preferences_key(line),
            }

    return None


def _extract_shared_preferences_key(line: str) -> str | None:
    match = re.search(r'put(?:string|charsequence)\(\s*["\']([^"\']+)["\']', line, flags=re.IGNORECASE)
    if match:
        return match.group(1)
    return None

OPEN_REDIRECT_RULE = DetectorFindingTemplate(
    rule_id="WEB-REDIRECT-001",
    title="Potential Open Redirect",
    message="A user-controlled value appears to reach a redirect sink.",
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    category=RuleCategory.OPEN_REDIRECT,
    owasp=["A01:2021 - Broken Access Control"],
    cwe=["CWE-601"],
    remediation="Restrict redirects to a fixed allowlist or force relative paths only.",
    tags=["web", "redirect", "open-redirect"],
)

AUTH_CHECK_RULE = DetectorFindingTemplate(
    rule_id="WEB-AUTH-001",
    title="Potential Missing Auth Check",
    message="A route appears to access request data without an obvious authentication guard.",
    severity=Severity.MEDIUM,
    confidence=Confidence.LOW,
    category=RuleCategory.AUTHENTICATION,
    owasp=["A01:2021 - Broken Access Control"],
    cwe=["CWE-306"],
    remediation="Require authentication or authorization checks before processing the route.",
    tags=["web", "auth", "guard"],
)

TEMPLATE_RULE = DetectorFindingTemplate(
    rule_id="WEB-TEMPLATE-001",
    title="Potential Template Injection or Unsafe Rendering",
    message="A user-controlled value appears to flow into a template rendering sink.",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    category=RuleCategory.TEMPLATE_INJECTION,
    owasp=["A03:2021 - Injection"],
    cwe=["CWE-94", "CWE-1336"],
    remediation="Pass data through safe template contexts and avoid rendering attacker-controlled template strings.",
    tags=["web", "template", "render"],
)

SCA_RULE = DetectorFindingTemplate(
    rule_id="SCA-PACKAGE-001",
    title="Known Vulnerable Dependency",
    message="A dependency matches a known vulnerable package pattern in the local advisory set.",
    severity=Severity.HIGH,
    confidence=Confidence.MEDIUM,
    category=RuleCategory.SCA,
    owasp=["A06:2021 - Vulnerable and Outdated Components"],
    cwe=["CWE-1104"],
    remediation="Upgrade or replace the vulnerable package version.",
    tags=["sca", "dependency", "cve"],
)

DEFAULT_SCA_BACKEND = LocalAdvisoryBackend()


@dataclass(slots=True, frozen=True)
class DetectionFinding:
    finding: Finding
    source: str


def _line_from_match(text: str, match_start: int) -> int:
    return text.count("\n", 0, match_start) + 1


def _make_finding(
    template: DetectorFindingTemplate,
    path: Path,
    relative_path: str,
    line: int,
    evidence: str,
    language: str | None = None,
    framework: str | None = None,
    metadata: dict[str, Any] | None = None,
    severity: Severity | None = None,
    confidence: Confidence | None = None,
) -> Finding:
    metadata = metadata or {}
    metadata = dict(metadata)
    metadata.setdefault("relative_path", relative_path)
    fingerprint_parts = [
        relative_path,
        str(line),
        str(metadata.get("package", "")),
        str(metadata.get("version", "")),
        evidence,
    ]
    fingerprint = ":".join(part.replace(":", "_") for part in fingerprint_parts if part)
    return Finding(
        id=f"{template.rule_id}:{fingerprint}",
        rule_id=template.rule_id,
        title=template.title,
        message=template.message,
        severity=severity or template.severity,
        confidence=confidence or template.confidence,
        location=CodeLocation(path=path, start_line=line),
        category=template.category.value,
        language=language,
        framework=framework,
        owasp=list(template.owasp),
        cwe=list(template.cwe),
        evidence=Evidence(snippet=evidence, start_line=line, end_line=line),
        remediation=template.remediation,
        status=FindingStatus.NEW,
        tags=list(template.tags),
        metadata=metadata,
    )


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[^'\"]{8,}"),
    re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"]?[^'\"]{8,}"),
    re.compile(r"(?i)-----begin [a-z ]*private key-----"),
)

SECRET_CONTEXT_HINTS: tuple[str, ...] = (
    "changeme",
    "dummy",
    "example",
    "example.com",
    "fake",
    "placeholder",
    "test",
    "your_api_key",
    "your_secret",
    "your_token",
)

SENSITIVE_SECRET_FILENAMES: tuple[str, ...] = (
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
)


def detect_secrets(parsed: ParsedDocument) -> list[Finding]:
    text = _read_text(parsed.path)
    findings: list[Finding] = []
    lines = text.splitlines()
    sensitive_file = _is_sensitive_secret_file(parsed.relative_path)

    for pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            line = _line_from_match(text, match.start())
            raw_line = lines[line - 1].strip() if line - 1 < len(lines) else match.group(0)
            if _looks_like_dummy_secret(raw_line):
                continue
            evidence = _mask_secret_line(raw_line)
            metadata = {
                "pattern": pattern.pattern,
                "masked": True,
                "cleartext_hint": "secret value masked in report",
            }
            if sensitive_file:
                metadata["sensitive_file"] = True
                metadata["priority"] = "high"
            findings.append(
                _make_finding(
                    SECRET_RULE,
                    path=parsed.path,
                    relative_path=parsed.relative_path,
                    line=line,
                    evidence=evidence,
                    language=parsed.language.value,
                    framework=parsed.framework,
                    metadata=metadata,
                )
            )

    return _dedupe(findings)


def _is_sensitive_secret_file(relative_path: str) -> bool:
    lowered = relative_path.lower()
    if lowered.endswith("/.env"):
        return True
    return any(lowered.endswith(name) or lowered == name for name in SENSITIVE_SECRET_FILENAMES)


def _looks_like_dummy_secret(line: str) -> bool:
    lowered = line.lower()
    return any(hint in lowered for hint in SECRET_CONTEXT_HINTS)


def _mask_secret_line(line: str) -> str:
    match = re.search(r"([:=]\s*)(['\"]?)([^'\"]{8,})(['\"]?)", line)
    if match is None:
        return line

    prefix = line[: match.start(3)]
    secret_value = match.group(3)
    suffix = line[match.end(3) :]
    if len(secret_value) <= 4:
        masked_value = "****"
    else:
        masked_value = f"{secret_value[:2]}***{secret_value[-2:]}"
    return f"{prefix}{masked_value}{suffix}"


def _line_has_assignment_taint(line: str, taint_state: TaintState | None, line_no: int | None = None) -> bool:
    return bool(line_uses_tainted_flow(line, taint_state, line_no))


def _merge_assignment_taint_metadata(
    metadata: dict[str, Any],
    line: str,
    taint_state: TaintState | None,
    line_no: int | None = None,
) -> dict[str, Any]:
    taint_metadata = taint_propagation_metadata(line, taint_state, line_no)
    if not taint_metadata:
        return metadata

    merged = dict(metadata)
    for key, value in taint_metadata.items():
        merged.setdefault(key, value)
    if "source_kind" not in merged and "taint_source_kind" in taint_metadata:
        merged["source_kind"] = taint_metadata["taint_source_kind"]
    return merged


def _has_string_escape_sanitizer(
    line: str,
    taint_state: TaintState | None,
    line_no: int | None = None,
) -> bool:
    if is_string_escape_sanitized_expression(line):
        return True
    taint_metadata = taint_propagation_metadata(line, taint_state, line_no)
    return bool(taint_metadata.get("taint_sanitized"))


def _has_url_allowlist_guard(
    line: str,
    taint_state: TaintState | None,
    line_no: int | None = None,
) -> bool:
    if is_url_allowlist_guard_expression(line):
        return True
    taint_metadata = taint_propagation_metadata(line, taint_state, line_no)
    return bool(taint_metadata.get("taint_guarded"))


def _auth_guard_metadata(line: str, parsed: ParsedDocument) -> dict[str, Any]:
    lowered = line.lower()
    if not is_auth_guard_reference(lowered):
        return {}

    metadata: dict[str, Any] = {
        "auth_guard": True,
        "auth_guard_kind": "auth_check",
    }
    if parsed.language in {Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT}:
        metadata["auth_model"] = "guard"
    if _line_has_any(
        lowered,
        (
            "app.use(",
            "router.use(",
            "appmiddleware",
            "routermiddleware",
            "authmiddleware",
            "middlewareauth",
            "withauth",
            "useauth(",
            "requireauth(",
        ),
    ):
        metadata["auth_model"] = "middleware"
        metadata["middleware_kind"] = "auth"
    elif _line_has_any(lowered, ("login_required", "permission_required")):
        metadata["auth_model"] = "decorator"
        metadata["guard_kind"] = "auth_check"
    elif _line_has_any(lowered, ("is_authenticated", "auth()->check(", "auth::check(")):
        metadata["auth_model"] = "predicate"
        metadata["guard_kind"] = "auth_check"
    elif is_role_guard_reference(lowered):
        metadata["auth_model"] = "role_check"
        metadata["auth_guard_kind"] = "role_check"
        metadata["guard_kind"] = "role_check"
        if _line_has_any(
            lowered,
            (
                "hasrole(",
                "hasroles(",
                "haspermission(",
                "haspermissions(",
                "hasanyrole(",
                "hasanyroles(",
                "can(",
                "authorize(",
                "gate::allows(",
                "gate::denies(",
                "gate::allowsany(",
            ),
        ):
            metadata["role_model"] = "rbac"
    return metadata


def _has_parameterized_query_sanitizer(line: str) -> bool:
    lowered = line.lower()
    if "+" in line or "f\"" in line or "f'" in line or ".format(" in lowered:
        return False

    safe_patterns = (
        r"\b(?:cursor|connection\.cursor\(\)|session|db\.session|engine|connection)\.execute\(\s*(?:text\()?[\"'][^\"']*(?:%s|%\([A-Za-z_][\w]*\)s|\?|:[A-Za-z_][\w]*)[^\"']*[\"']\s*\)?\s*,",
        r"\b(?:cursor|connection\.cursor\(\)|session|db\.session|engine|connection)\.executemany\(\s*(?:text\()?[\"'][^\"']*(?:%s|%\([A-Za-z_][\w]*\)s|\?|:[A-Za-z_][\w]*)[^\"']*[\"']\s*\)?\s*,",
        r"\bobjects\.raw\(\s*[\"'][^\"']*(?:%s|%\([A-Za-z_][\w]*\)s|\?|:[A-Za-z_][\w]*)[^\"']*[\"']\s*,",
        r"\bquery\.from_statement\(\s*text\(\s*[\"'][^\"']*(?:%s|%\([A-Za-z_][\w]*\)s|\?|:[A-Za-z_][\w]*)[^\"']*[\"']\s*\)\s*,",
        r"\bjdbctemplate\.(?:query|update)\(\s*[\"'][^\"']*\?[^\"']*[\"']\s*,\s*(?:[A-Za-z_$][\w$]*\s*,\s*)?[A-Za-z_$][\w$]*",
        r"\bnamedparameterjdbctemplate\.(?:query|update)\(\s*[\"'][^\"']*:[A-Za-z_][\w]*[^\"']*[\"']\s*,\s*[A-Za-z_$][\w$]*",
        r"\bconnection\.preparestatement\(\s*[\"'][^\"']*\?[^\"']*[\"']\s*\)",
        r"\b(?:entitymanager|session)\.create(?:native)?query\(\s*[\"'][^\"']*:[A-Za-z_][\w]*[^\"']*[\"']\s*\)\.setparameter\(",
    )
    return any(re.search(pattern, lowered, re.IGNORECASE) for pattern in safe_patterns)


def _looks_like_sql_interpolation(line: str, taint_state: TaintState | None = None, line_no: int | None = None) -> bool:
    lowered = line.lower()
    if "select " not in lowered and "insert " not in lowered and "update " not in lowered and "delete " not in lowered:
        return False
    if _has_parameterized_query_sanitizer(line):
        return False
    if "+" in line or "f\"" in line or "f'" in line or ".format(" in lowered:
        return True
    return "execute(" in lowered or "query(" in lowered or _line_has_assignment_taint(line, taint_state, line_no)


def _looks_like_orm_query(line: str, taint_state: TaintState | None = None, line_no: int | None = None) -> bool:
    lowered = line.lower()
    sink_patterns = (
        ".raw(",
        ".executemany(",
        ".from_statement(",
        "session.execute(",
        "db.session.execute(",
        "engine.execute(",
        "connection.execute(",
        "cursor.execute(",
        "objects.raw(",
        "objects.extra(",
        "query.from_statement(",
        "text(",
    )
    source_patterns = (
        "request.args",
        "request.form",
        "request.values",
        "request.json",
        "request.get_json",
        "request.GET",
        "request.POST",
        "request.COOKIES",
        "request.META",
        "req.query",
        "req.body",
        "user_input",
        "sql",
    )
    return _line_has_any(lowered, sink_patterns) and not _has_parameterized_query_sanitizer(line) and (
        _line_has_any(lowered, source_patterns)
        or "+" in line
        or "f\"" in line
        or "f'" in line
        or ".format(" in lowered
        or _line_has_assignment_taint(line, taint_state, line_no)
    )


def _line_has_any(line: str, patterns: tuple[str, ...]) -> bool:
    lowered = line.lower()
    return any(pattern.lower() in lowered for pattern in patterns)


def _express_source_kind(line: str) -> str | None:
    lowered = line.lower()
    if is_query_source_reference(line):
        return SourceKind.QUERY.value
    if is_body_source_reference(line):
        return SourceKind.BODY.value
    if is_cookie_source_reference(line):
        return SourceKind.COOKIES.value
    if "req.params" in lowered or "request.params" in lowered:
        return SourceKind.ROUTE_PARAM.value
    if is_header_source_reference(line):
        return SourceKind.HEADERS.value
    return None


def _express_flow_metadata(parsed: ParsedDocument, line: str, sink_kind: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    if parsed.framework == Framework.EXPRESS:
        metadata["framework_model"] = "express"
        metadata["flow_model"] = "request_to_sink"
        source_kind = _express_source_kind(line)
        if source_kind is not None:
            metadata["source_kind"] = source_kind
        metadata["sink_kind"] = sink_kind
        if _line_has_any(line, ("app.get(", "app.post(", "router.get(", "router.post(", "app.use(", "router.use(")):
            metadata["handler_kind"] = "route_handler"
    return metadata


def _nextjs_source_kind(line: str) -> str | None:
    lowered = line.lower()
    if is_query_source_reference(line):
        return SourceKind.SEARCH_PARAMS.value
    if is_cookie_source_reference(line) or "cookies(" in lowered or "cookies().get(" in lowered:
        return SourceKind.COOKIES.value
    if is_header_source_reference(line):
        return SourceKind.HEADERS.value
    if is_body_source_reference(line):
        return SourceKind.BODY.value
    return None


def _nextjs_flow_metadata(parsed: ParsedDocument, line: str, sink_kind: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    if parsed.framework == Framework.NEXTJS:
        metadata["framework_model"] = "nextjs"
        metadata["flow_model"] = "request_to_sink"
        source_kind = _nextjs_source_kind(line)
        if source_kind is not None:
            metadata["source_kind"] = source_kind
        metadata["sink_kind"] = sink_kind
        if _line_has_any(line, ("nextresponse.redirect(", "nextresponse.rewrite(", "nextresponse.json(", "redirect(")):
            metadata["handler_kind"] = "route_handler"
    return metadata


def _django_source_kind(line: str) -> str | None:
    lowered = line.lower()
    if is_query_source_reference(line):
        return SourceKind.QUERY.value
    if is_body_source_reference(line):
        return SourceKind.BODY.value
    if is_cookie_source_reference(line):
        return SourceKind.COOKIES.value
    if is_header_source_reference(line):
        return SourceKind.HEADERS.value
    if is_auth_context_reference(line):
        return SourceKind.AUTH_CONTEXT.value
    return None


def _django_flow_metadata(parsed: ParsedDocument, line: str, sink_kind: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    if parsed.framework == Framework.DJANGO:
        metadata["framework_model"] = "django"
        metadata["flow_model"] = "request_to_sink"
        source_kind = _django_source_kind(line)
        if source_kind is not None:
            metadata["source_kind"] = source_kind
        metadata["sink_kind"] = sink_kind
    return metadata


def _orm_query_metadata(parsed: ParsedDocument, line: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    lowered = line.lower()
    if parsed.language != Language.PYTHON:
        return metadata

    metadata["flow_model"] = "user_input_to_orm_query"
    metadata["sink_kind"] = "orm_query"

    if parsed.framework == Framework.DJANGO or _line_has_any(
        lowered,
        (
            "django.db",
            "objects.raw(",
            "objects.extra(",
            "connection.cursor(",
            "cursor.execute(",
            "from django",
        ),
    ):
        metadata["framework_model"] = "django"
        metadata["orm_model"] = "django_orm"
    elif parsed.framework in {Framework.FLASK, Framework.FASTAPI} or _line_has_any(
        lowered,
        (
            "sqlalchemy",
            "session.execute(",
            "db.session.execute(",
            "engine.execute(",
            "connection.execute(",
            "text(",
        ),
    ):
        metadata["framework_model"] = str(parsed.framework) if parsed.framework is not None else "python"
        metadata["orm_model"] = "sqlalchemy"
    else:
        metadata["framework_model"] = str(parsed.framework) if parsed.framework is not None else "python"
        metadata["orm_model"] = "generic_orm"

    if _line_has_any(
        lowered,
        (
            "request.args",
            "request.form",
            "request.values",
            "request.json",
            "request.get_json",
            "request.GET",
            "request.POST",
            "request.COOKIES",
            "request.META",
            "req.query",
            "req.body",
            "user_input",
        ),
    ):
        metadata["source_kind"] = "request_input"
    if _line_has_any(lowered, ("objects.raw(", ".raw(", "text(", "execute(", "executemany(", "from_statement(")):
        metadata["query_kind"] = "raw_sql"
    return metadata


def _file_access_metadata(parsed: ParsedDocument, line: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    if parsed.language != Language.PYTHON:
        return metadata

    metadata["flow_model"] = "request_input_to_file_sink"
    metadata["sink_kind"] = "file_access"
    metadata["framework_model"] = str(parsed.framework) if parsed.framework is not None else "python"

    lowered = line.lower()
    if _line_has_any(
        lowered,
        (
            "request.args",
            "request.form",
            "request.values",
            "request.json",
            "request.get_json",
            "request.GET",
            "request.POST",
            "request.COOKIES",
            "request.META",
            "req.query",
            "req.body",
            "user_input",
            "filename",
            "path",
            "file",
        ),
    ):
        metadata["source_kind"] = "request_input"

    if _line_has_any(
        lowered,
        (
            "open(",
            "os.open(",
            "read_text(",
            "read_bytes(",
            "file_response(",
            "fileresponse(",
        ),
    ):
        metadata["file_operation"] = "open"
    elif _line_has_any(lowered, ("send_file(", "send_from_directory(")):
        metadata["file_operation"] = "send"
    elif _line_has_any(lowered, ("copy(", "copyfile(", "move(")):
        metadata["file_operation"] = "copy_or_move"

    return metadata


def _looks_like_spring_ssrf(line: str, taint_state: TaintState | None = None) -> bool:
    lowered = line.lower()
    sink_patterns = (
        "resttemplate.getforobject(",
        "resttemplate.exchange(",
        "webclient.get(",
        "webclient.post(",
        "webclient.uri(",
        "okhttpclient.newcall(",
        "httpclient.execute(",
        "urlconnection.openconnection(",
    )
    return _line_has_any(lowered, sink_patterns)


def _looks_like_spring_open_redirect(line: str, taint_state: TaintState | None = None) -> bool:
    lowered = line.lower()
    sink_patterns = (
        'return "redirect:',
        "return 'redirect:",
        "redirectview.seturl(",
        'modelandview.setviewname("redirect:',
        "modelandview.setviewname('redirect:",
        "sendredirect(",
    )
    return _line_has_any(lowered, sink_patterns)


def _looks_like_spring_path_traversal(line: str, taint_state: TaintState | None = None) -> bool:
    lowered = line.lower()
    sink_patterns = (
        "files.readstring(",
        "files.readallbytes(",
        "files.newinputstream(",
        "fileinputstream(",
        "fileresource(",
        "servletcontext.getresourceasstream(",
    )
    return _line_has_any(lowered, sink_patterns)


def _looks_like_spring_file_access(line: str, taint_state: TaintState | None = None) -> bool:
    lowered = line.lower()
    sink_patterns = (
        "files.copy(",
        "files.delete(",
        "files.move(",
        "files.newoutputstream(",
        "fileoutputstream(",
        "fileresource(",
        "resource.getinputstream(",
    )
    return _line_has_any(lowered, sink_patterns)


def _looks_like_spring_sql_query(line: str, taint_state: TaintState | None = None) -> bool:
    lowered = line.lower()
    sink_patterns = (
        "jdbctemplate.query(",
        "jdbctemplate.update(",
        "jdbctemplate.execute(",
        "namedparameterjdbctemplate.query(",
        "namedparameterjdbctemplate.update(",
        "entitymanager.createquery(",
        "entitymanager.createnativequery(",
        "session.createquery(",
        "session.createnativequery(",
        "connection.preparestatement(",
        "statement.executequery(",
        "statement.executeupdate(",
        "statement.execute(",
        "dslcontext.fetch(",
        "dslcontext.execute(",
    )
    return _line_has_any(lowered, sink_patterns) and not _has_parameterized_query_sanitizer(line)


def _looks_like_spring_deserialization(line: str) -> bool:
    lowered = line.lower()
    if "objectinputstream" in lowered and ("readobject(" in lowered or "readunshared(" in lowered):
        return True
    if "objectmapper" in lowered and "readvalue(" in lowered:
        return True
    sink_patterns = (
        "objectmapper.readvalue(",
        "objectmapper().readvalue(",
        "new objectmapper().readvalue(",
        "xmlmapper.readvalue(",
        "gson.fromjson(",
        "jsonmapper.readvalue(",
        "objectinputstream.readobject(",
        "objectinputstream().readobject(",
        "new objectinputstream().readobject(",
        "new objectinputstream(",
        "objectinputstream.readunshared(",
        "objectinputstream().readunshared(",
        "serializationutils.deserialize(",
        "serializationutils().deserialize(",
        "kryo.readobject(",
        "kryo().readobject(",
        "kryo.readclassandobject(",
        "kryo().readclassandobject(",
        "yaml.load(",
        "yaml().load(",
        "snakeyaml.load(",
        "snakeyaml().load(",
        "snakeyaml.loadas(",
        "snakeyaml().loadas(",
        "jackson2jsonredisserializer.deserialize(",
        "jackson2jsonredisserializer().deserialize(",
    )
    return _line_has_any(lowered, sink_patterns)


def _android_manifest_findings(parsed: ParsedDocument) -> list[Finding]:
    if parsed.language != Language.XML or parsed.framework != Framework.ANDROID.value:
        return []
    manifest = parsed.metadata.get("android_manifest")
    if not isinstance(manifest, dict):
        return []

    package = manifest.get("package")
    components = manifest.get("components", [])
    if not isinstance(components, list):
        return []

    findings: list[Finding] = []
    for permission in manifest.get("uses_permissions", []):
        if permission not in _ANDROID_DANGEROUS_PERMISSIONS:
            continue
        permission_name = permission.split(".")[-1]
        metadata = {
            "framework_model": "android",
            "manifest_kind": "permission",
            "permission_name": permission,
            "permission_risk": "dangerous",
            "android_package": package,
        }
        findings.append(
            _make_finding(
                ANDROID_DANGEROUS_PERMISSION_RULE,
                path=parsed.path,
                relative_path=parsed.relative_path,
                line=1,
                evidence=permission_name,
                language=parsed.language.value,
                framework=parsed.framework,
                metadata=metadata,
            )
        )

    for component in components:
        if not isinstance(component, dict):
            continue
        kind = component.get("kind")
        exported = component.get("exported") is True
        if kind not in {"activity", "activity-alias", "receiver"} or not exported:
            continue

        name = component.get("name") or "<unknown>"
        intent_filter_count = component.get("intent_filter_count")
        permission = component.get("permission")
        metadata = {
            "framework_model": "android",
            "component_kind": kind,
            "component_name": name,
            "component_exported": True,
            "component_permission": permission,
            "intent_filter_count": intent_filter_count,
            "android_package": package,
        }
        if kind in {"activity", "activity-alias"}:
            metadata["manifest_kind"] = "activity"
            findings.append(
                _make_finding(
                    ANDROID_ACTIVITY_RULE,
                    path=parsed.path,
                    relative_path=parsed.relative_path,
                    line=1,
                    evidence=str(name),
                    language=parsed.language.value,
                    framework=parsed.framework,
                    metadata=metadata,
                )
            )
            continue

        metadata["manifest_kind"] = "receiver"
        findings.append(
            _make_finding(
                ANDROID_RECEIVER_RULE,
                path=parsed.path,
                relative_path=parsed.relative_path,
                line=1,
                evidence=str(name),
                language=parsed.language.value,
                framework=parsed.framework,
                metadata=metadata,
            )
        )

    return findings


def _android_shared_preferences_findings(parsed: ParsedDocument) -> list[Finding]:
    if parsed.language not in {Language.JAVA, Language.KOTLIN}:
        return []

    text = _read_text(parsed.path)
    lines = text.splitlines()
    findings: list[Finding] = []
    android_context = parsed.framework == Framework.ANDROID.value or "sharedpreferences" in text.lower() or "android.content.sharedpreferences" in text.lower()
    if not android_context:
        return findings

    for index, line in enumerate(lines, start=1):
        window_start = max(0, index - 3)
        window_end = min(len(lines), index + 2)
        window = "\n".join(lines[window_start:window_end])
        metadata = _looks_like_android_shared_preferences(line, window)
        if metadata is None:
            continue
        metadata = {
            **metadata,
            "framework_model": "android",
            "manifest_kind": "storage",
            "android_package": parsed.metadata.get("android_manifest", {}).get("package") if isinstance(parsed.metadata.get("android_manifest"), dict) else None,
        }
        findings.append(
            _make_finding(
                ANDROID_SHARED_PREFERENCES_RULE,
                path=parsed.path,
                relative_path=parsed.relative_path,
                line=index,
                evidence=line.strip(),
                language=parsed.language.value,
                framework=Framework.ANDROID.value,
                metadata=metadata,
            )
        )

    return findings


def _looks_like_laravel_route(line: str) -> bool:
    lowered = line.lower()
    return _line_has_any(
        lowered,
        (
            "route::get(",
            "route::post(",
            "route::put(",
            "route::delete(",
            "route::patch(",
            "route::any(",
            "route::match(",
        ),
    )


def _looks_like_laravel_ssrf(line: str, taint_state: TaintState | None = None) -> bool:
    lowered = line.lower()
    sink_patterns = (
        "http::get(",
        "http::post(",
        "http::put(",
        "http::delete(",
        "guzzlehttp\\client(",
        "client->get(",
        "client->post(",
        "client->request(",
        "file_get_contents(",
        "curl_exec(",
    )
    return _line_has_any(lowered, sink_patterns)


def _looks_like_laravel_open_redirect(line: str, taint_state: TaintState | None = None) -> bool:
    lowered = line.lower()
    sink_patterns = (
        "redirect(",
        "redirect()->to(",
        "redirect()->away(",
        "return redirect(",
        "return redirect()->to(",
        "return redirect()->away(",
        "response()->redirectto(",
    )
    return _line_has_any(lowered, sink_patterns)


def _looks_like_laravel_path_traversal(line: str, taint_state: TaintState | None = None) -> bool:
    lowered = line.lower()
    sink_patterns = (
        "file_get_contents(",
        "storage::get(",
        "storage::download(",
        "storage::put(",
        "readfile(",
        "fopen(",
        "fread(",
        "scandir(",
        "glob(",
    )
    return _line_has_any(lowered, sink_patterns)


def _looks_like_laravel_file_access(line: str, taint_state: TaintState | None = None) -> bool:
    lowered = line.lower()
    sink_patterns = (
        "storage::get(",
        "storage::download(",
        "storage::put(",
        "storage::delete(",
        "file_get_contents(",
        "readfile(",
        "fopen(",
        "fread(",
    )
    return _line_has_any(lowered, sink_patterns)


def _looks_like_laravel_process(line: str, taint_state: TaintState | None = None) -> bool:
    lowered = line.lower()
    sink_patterns = (
        "shell_exec(",
        "exec(",
        "system(",
        "passthru(",
        "proc_open(",
        "popen(",
        "pcntl_exec(",
        "symfony\\component\\process\\process(",
        "process->",
        "``",
    )
    return _line_has_any(lowered, sink_patterns)


def _looks_like_blade_template(line: str, taint_state: TaintState | None = None, line_no: int | None = None) -> bool:
    lowered = line.lower()
    sink_patterns = (
        "view(",
        "view()->make(",
        "view::make(",
        "response()->view(",
        "blade::render(",
        "blade::compilestring(",
    )
    source_patterns = (
        "request->input(",
        "request()->input(",
        "request->query(",
        "request()->query(",
        "request->all(",
        "request->post(",
        "request()->post(",
        "request('",
        "$request->input(",
        "$request->query(",
        "$request->all(",
        "$request->post(",
        "$request->header(",
        "$request->cookie(",
        "auth()->",
        "user_input",
    )
    return _line_has_any(lowered, sink_patterns) and (
        _line_has_any(lowered, source_patterns) or _line_has_assignment_taint(line, taint_state, line_no)
    )


def _spring_window_text(lines: list[str], index: int) -> str:
    start = max(0, index - 6)
    end = index
    return "\n".join(lines[start:end]).lower()


def _spring_source_kind(lines: list[str], index: int) -> str | None:
    window = _spring_window_text(lines, index)
    if any(marker in window for marker in ("@requestparam", "requestparam(")) or is_query_source_reference(window):
        return SourceKind.QUERY.value
    if any(marker in window for marker in ("@pathvariable", "pathvariable(")):
        return SourceKind.PATH.value
    if is_body_source_reference(window):
        return SourceKind.BODY.value
    if is_cookie_source_reference(window) or any(marker in window for marker in ("@cookievalue", "getcookies(", "getcookie(")):
        return SourceKind.COOKIES.value
    if any(marker in window for marker in ("@requestheader", "requestheader(")) or is_header_source_reference(window):
        return SourceKind.HEADERS.value
    if any(marker in window for marker in ("getparameter(", "getparameterstring(", "getparameternames(")):
        return SourceKind.QUERY.value
    if any(marker in window for marker in ("getheader(",)):
        return SourceKind.HEADERS.value
    if any(marker in window for marker in ("getreader(", "getinputstream(")):
        return SourceKind.BODY.value
    if is_auth_context_reference(window):
        return SourceKind.AUTH_CONTEXT.value
    return None


def _spring_handler_kind(lines: list[str], index: int) -> str | None:
    window = _spring_window_text(lines, index)
    if any(marker in window for marker in ("@restcontroller", "@controller", "@requestmapping", "@getmapping", "@postmapping", "@putmapping", "@deletemapping", "@patchmapping")):
        return "controller_method"
    if any(marker in window for marker in ("@repository", "jdbctemplate", "entitymanager", "springdata", "jpacrepository")):
        return "repository_method"
    if any(marker in window for marker in ("@webservlet", "extends httpservlet", "doget(", "dopost(", "doput(", "dodelete(", "service(")):
        return "servlet_method"
    return None


def _spring_entry_kind(lines: list[str], index: int) -> str | None:
    window = _spring_window_text(lines, index)
    if any(marker in window for marker in ("@webservlet", "extends httpservlet", "doget(", "dopost(", "doput(", "dodelete(", "service(")):
        return "servlet"
    if any(marker in window for marker in ("@restcontroller", "@controller", "@requestmapping", "@getmapping", "@postmapping", "@putmapping", "@deletemapping", "@patchmapping")):
        return "controller"
    if any(marker in window for marker in ("@repository", "jdbctemplate", "entitymanager", "springdata", "jpacrepository")):
        return "repository"
    return None


def _spring_flow_metadata(parsed: ParsedDocument, lines: list[str], index: int, sink_kind: str) -> dict[str, Any]:
    window = _spring_window_text(lines, index)
    metadata: dict[str, Any] = {}
    if parsed.language not in {Language.JAVA, Language.KOTLIN}:
        return metadata
    if not (
        parsed.framework == Framework.SPRING
        or any(
            marker in window
            for marker in (
                "@restcontroller",
                "@controller",
                "@requestmapping",
                "@getmapping",
                "@postmapping",
                "@putmapping",
                "@deletemapping",
                "@patchmapping",
                "org.springframework",
            )
        )
    ):
        return metadata

    metadata["framework_model"] = "spring"
    metadata["flow_model"] = "request_to_sink"
    metadata["sink_kind"] = sink_kind
    source_kind = _spring_source_kind(lines, index)
    if source_kind is not None:
        metadata["source_kind"] = source_kind
    entry_kind = _spring_entry_kind(lines, index)
    if entry_kind is not None:
        metadata["entry_kind"] = entry_kind
    handler_kind = _spring_handler_kind(lines, index)
    if handler_kind is not None:
        metadata["handler_kind"] = handler_kind
    if any(marker in window for marker in ("@getmapping", "@postmapping", "@putmapping", "@deletemapping", "@patchmapping", "@requestmapping")):
        metadata["mapping_kind"] = next(
            marker.strip("@")
            for marker in ("@getmapping", "@postmapping", "@putmapping", "@deletemapping", "@patchmapping", "@requestmapping")
            if marker in window
        )
    if any(marker in window for marker in ("@requestparam", "@pathvariable", "@requestbody", "@requestheader")):
        metadata["spring_parameter"] = next(
            marker.strip("@")
            for marker in ("@requestparam", "@pathvariable", "@requestbody", "@requestheader")
            if marker in window
        )
    return metadata


def _spring_deserialization_metadata(parsed: ParsedDocument, lines: list[str], index: int) -> dict[str, Any]:
    window = _spring_window_text(lines, index)
    current_line = lines[index - 1].lower() if 0 <= index - 1 < len(lines) else ""
    metadata = _spring_flow_metadata(parsed, lines, index, "deserialization")
    if not metadata:
        return metadata

    metadata["sink_kind"] = "deserialization"
    if "objectinputstream" in current_line and ("readobject(" in current_line or "readunshared(" in current_line):
        metadata["deserialization_kind"] = "java_serialization"
    elif "objectmapper" in current_line and "readvalue(" in current_line:
        metadata["deserialization_kind"] = "object_mapper"
    elif "gson" in current_line and "fromjson(" in current_line:
        metadata["deserialization_kind"] = "gson"
    elif "yaml" in current_line and "load(" in current_line:
        metadata["deserialization_kind"] = "yaml"
    elif "jackson2jsonredisserializer" in current_line and "deserialize(" in current_line:
        metadata["deserialization_kind"] = "redis_json"
    else:
        metadata["deserialization_kind"] = next(
            (
                kind
                for kind, markers in (
                    ("object_mapper", ("objectmapper.readvalue(", "objectmapper().readvalue(", "new objectmapper().readvalue(", "jsonmapper.readvalue(", "xmlmapper.readvalue(")),
                    ("gson", ("gson.fromjson(", "gson().fromjson(")),
                    ("java_serialization", ("objectinputstream.readobject(", "objectinputstream().readobject(", "new objectinputstream().readobject(", "new objectinputstream(", "objectinputstream.readunshared(", "objectinputstream().readunshared(", "serializationutils.deserialize(", "serializationutils().deserialize(", "kryo.readobject(", "kryo().readobject(", "kryo.readclassandobject(", "kryo().readclassandobject(")),
                    ("yaml", ("yaml.load(", "yaml().load(", "snakeyaml.load(", "snakeyaml().load(", "snakeyaml.loadas(", "snakeyaml().loadas(")),
                    ("redis_json", ("jackson2jsonredisserializer.deserialize(", "jackson2jsonredisserializer().deserialize(")),
                )
                if any(marker in window for marker in markers)
            ),
            "generic",
        )
    if is_body_source_reference(window):
        metadata["source_kind"] = metadata.get("source_kind", "body")
    return metadata


def _laravel_window_text(lines: list[str], index: int) -> str:
    start = max(0, index - 6)
    end = index + 1
    return "\n".join(lines[start:end]).lower()


def _laravel_source_kind(lines: list[str], index: int) -> str | None:
    window = _laravel_window_text(lines, index)
    if is_query_source_reference(window):
        return SourceKind.QUERY.value
    if any(marker in window for marker in ("$request->input(", "request()->input(", "$request->all(", "$request->post(", "$request->json(", "request('")):
        return SourceKind.REQUEST_INPUT.value
    if is_cookie_source_reference(window):
        return SourceKind.COOKIES.value
    if is_header_source_reference(window):
        return SourceKind.HEADERS.value
    if is_auth_context_reference(window):
        return SourceKind.AUTH_CONTEXT.value
    return None


def _laravel_entry_kind(lines: list[str], index: int) -> str | None:
    window = _laravel_window_text(lines, index)
    if any(marker in window for marker in ("route::get(", "route::post(", "route::put(", "route::delete(", "route::patch(", "route::any(", "route::match(")):
        return "route_definition"
    if any(marker in window for marker in ("function (request ", "function(request ", "public function", "protected function", "private function")):
        return "controller_method"
    return None


def _laravel_flow_metadata(parsed: ParsedDocument, lines: list[str], index: int, sink_kind: str) -> dict[str, Any]:
    window = _laravel_window_text(lines, index)
    metadata: dict[str, Any] = {}
    if parsed.language != Language.PHP:
        return metadata
    if not (
        parsed.framework == Framework.LARAVEL
        or any(
            marker in window
            for marker in (
                "route::get(",
                "route::post(",
                "route::put(",
                "route::delete(",
                "route::patch(",
                "route::any(",
                "route::match(",
                "illuminate\\",
                "laravel",
            )
        )
    ):
        return metadata

    metadata["framework_model"] = "laravel"
    metadata["flow_model"] = "request_to_sink"
    metadata["sink_kind"] = sink_kind
    source_kind = _laravel_source_kind(lines, index)
    if source_kind is not None:
        metadata["source_kind"] = source_kind
    entry_kind = _laravel_entry_kind(lines, index)
    if entry_kind is not None:
        metadata["entry_kind"] = entry_kind
    if any(marker in window for marker in ("route::get(", "route::post(", "route::put(", "route::delete(", "route::patch(", "route::any(", "route::match(")):
        route_map = {
            "route::get(": "get",
            "route::post(": "post",
            "route::put(": "put",
            "route::delete(": "delete",
            "route::patch(": "patch",
            "route::any(": "any",
            "route::match(": "match",
        }
        metadata["route_kind"] = next(value for marker, value in route_map.items() if marker in window)
    return metadata


def _laravel_process_metadata(parsed: ParsedDocument, lines: list[str], index: int) -> dict[str, Any]:
    metadata = _laravel_flow_metadata(parsed, lines, index, "process_execution")
    if not metadata:
        return metadata

    current_line = lines[index - 1].lower() if 0 <= index - 1 < len(lines) else ""
    metadata["process_kind"] = "shell_command"
    window = _laravel_window_text(lines, index)
    if any(marker in current_line for marker in ("shell_exec(", "exec(", "system(", "passthru(", "pcntl_exec(")):
        metadata["process_kind"] = "shell"
    elif any(marker in current_line for marker in ("proc_open(", "popen(")):
        metadata["process_kind"] = "spawn"
    elif "symfony\\component\\process\\process" in current_line or "process->" in current_line:
        metadata["process_kind"] = "process_object"
    return metadata


def _blade_flow_metadata(parsed: ParsedDocument, lines: list[str], index: int) -> dict[str, Any]:
    metadata = _laravel_flow_metadata(parsed, lines, index, "template_render")
    if not metadata:
        return metadata

    metadata["flow_model"] = "context_to_template_sink"
    metadata["template_model"] = "blade"
    window = _laravel_window_text(lines, index)
    if "blade::render(" in window:
        metadata["template_sink"] = "blade_render"
        metadata["template_kind"] = "string_template"
    elif "view()->make(" in window or "view::make(" in window or "response()->view(" in window or "view(" in window:
        metadata["template_sink"] = "view"
        metadata["template_kind"] = "view_template"
    else:
        metadata["template_sink"] = "render"
        metadata["template_kind"] = "template"
    return metadata


def _template_flow_metadata(parsed: ParsedDocument, line: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    if parsed.language in {Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT}:
        if parsed.framework == Framework.DJANGO:
            metadata["framework_model"] = "django"
            metadata["template_model"] = "django"
        elif parsed.framework == Framework.FLASK:
            metadata["framework_model"] = "flask"
            metadata["template_model"] = "jinja2"
        elif parsed.framework == Framework.NEXTJS:
            metadata["framework_model"] = "nextjs"
            metadata["template_model"] = "react"
        elif parsed.framework == Framework.REACT:
            metadata["framework_model"] = "react"
            metadata["template_model"] = "react"
        else:
            metadata["template_model"] = "generic"
        metadata["flow_model"] = "context_to_template_sink"
        metadata["sink_kind"] = "template_render"
        if _line_has_any(line, ("render_template(", "render_to_string(", "get_template(", "template.render(", "jinja2.template", "template(", "response.render(", "res.render(", "render(", "dangerouslysetinnerhtml")):
            metadata["template_sink"] = "render"
    return metadata


def _react_dom_flow_metadata(parsed: ParsedDocument, line: str) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    if parsed.framework == Framework.REACT:
        metadata["framework_model"] = "react"
        metadata["flow_model"] = "prop_to_dom_sink"
        metadata["sink_kind"] = "dom_sink"
        if _line_has_any(line, ("dangerouslysetinnerhtml", "innerhtml", "document.write")):
            metadata["dom_sink"] = "innerhtml"
        if _line_has_any(line, ("dangerouslysetinnerhtml",)):
            metadata["react_sink"] = "dangerouslySetInnerHTML"
        if _line_has_any(line, ("useeffect(", "uselayouteffect(", "usememo(", "usecallback(")):
            metadata["react_lifecycle"] = "hook"
    return metadata


def _looks_like_ssrf(line: str, taint_state: TaintState | None = None, line_no: int | None = None) -> bool:
    sink_patterns = (
        "requests.get(",
        "requests.post(",
        "requests.put(",
        "requests.delete(",
        "httpx.get(",
        "httpx.post(",
        "urllib.request.urlopen(",
        "session.get(",
        "session.post(",
        "fetch(",
        "axios.get(",
        "axios.post(",
    )
    source_patterns = (
        "request.args",
        "request.form",
        "request.values",
        "request.get",
        "request.query",
        "request.GET",
        "request.POST",
        "request.COOKIES",
        "request.META",
        "request.cookies",
        "req.cookies",
        "cookies().get",
        "req.query",
        "req.body",
        "user_input",
        "url",
        "uri",
        "next_url",
    )
    return _line_has_any(line, sink_patterns) and not _has_url_allowlist_guard(line, taint_state, line_no) and (
        _line_has_any(line, source_patterns) or _line_has_assignment_taint(line, taint_state, line_no)
    )


def _looks_like_path_traversal(line: str, taint_state: TaintState | None = None, line_no: int | None = None) -> bool:
    sink_patterns = (
        "open(",
        "read_text(",
        "read_bytes(",
        "os.open(",
        "pathlib.path(",
        "path.join(",
        "fs.readfile(",
        "fs.readfilesync(",
        "createReadStream(",
        "send_file(",
    )
    source_patterns = (
        "..",
        "request.args",
        "request.form",
        "request.values",
        "request.GET",
        "request.POST",
        "request.COOKIES",
        "request.META",
        "request.cookies",
        "req.cookies",
        "req.query",
        "req.body",
        "user_input",
        "filename",
        "path",
    )
    return _line_has_any(line, sink_patterns) and (
        _line_has_any(line, source_patterns) or _line_has_assignment_taint(line, taint_state, line_no)
    )


def _looks_like_file_access(line: str, taint_state: TaintState | None = None, line_no: int | None = None) -> bool:
    lowered = line.lower()
    sink_patterns = (
        "open(",
        "read_text(",
        "read_bytes(",
        "os.open(",
        "pathlib.path(",
        "send_file(",
        "send_from_directory(",
        "file_response(",
        "fileresponse(",
        "shutil.copy(",
        "shutil.copyfile(",
        "shutil.move(",
    )
    source_patterns = (
        "request.args",
        "request.form",
        "request.values",
        "request.GET",
        "request.POST",
        "request.COOKIES",
        "request.META",
        "request.cookies",
        "req.cookies",
        "req.query",
        "req.body",
        "user_input",
        "filename",
        "path",
        "file",
    )
    return _line_has_any(lowered, sink_patterns) and (
        _line_has_any(lowered, source_patterns) or _line_has_assignment_taint(line, taint_state, line_no)
    )


def _looks_like_open_redirect(line: str, taint_state: TaintState | None = None, line_no: int | None = None) -> bool:
    sink_patterns = (
        "redirect(",
        "httpresponseredirect(",
        "res.redirect(",
        "response.redirect(",
    )
    source_patterns = (
        "request.args.get(\"next\")",
        "request.args.get('next')",
        "request.GET.get(\"next\")",
        "request.GET.get('next')",
        "request.GET.get(\"redirect\")",
        "request.GET.get('redirect')",
        "request.GET.get(\"url\")",
        "request.GET.get('url')",
        "request.GET.get(\"uri\")",
        "request.GET.get('uri')",
        "request.GET.get(\"next_url\")",
        "request.GET.get('next_url')",
        "request.GET.get(\"redirect_url\")",
        "request.GET.get('redirect_url')",
        "request.GET.get(\"return_url\")",
        "request.GET.get('return_url')",
        "request.POST.get(\"next\")",
        "request.POST.get('next')",
        "request.POST.get(\"redirect\")",
        "request.POST.get('redirect')",
        "request.cookies.get(\"next\")",
        "request.cookies.get('next')",
        "request.cookies.get(\"redirect\")",
        "request.cookies.get('redirect')",
        "request.user",
        "req.user",
        "authentication",
        "principal",
        "auth()->user(",
        "auth::user(",
        "req.query.next",
        "req.body.next",
        "req.cookies.next",
        "req.cookies.redirect",
        "next_url",
        "redirect_url",
        "url",
    )
    return _line_has_any(line, sink_patterns) and not _has_url_allowlist_guard(line, taint_state, line_no) and (
        _line_has_any(line, source_patterns) or _line_has_assignment_taint(line, taint_state, line_no)
    )


def _looks_like_missing_auth_check(text: str, language: Language) -> bool:
    lowered = text.lower()
    auth_markers = tuple(marker.lower() for marker in (
        "login_required",
        "permission_required",
        "auth_required",
        "requires_auth",
        "ensureauthenticated",
        "authenticate",
    ))
    middleware_markers = tuple(marker.lower() for marker in (
        "app.use(requireauth",
        "router.use(requireauth",
        "app.use(authmiddleware",
        "router.use(authmiddleware",
        "app.use(withauth",
        "router.use(withauth",
        "useauth(",
        "withauth(",
        "requireauth(",
        "authmiddleware(",
        "middlewareauth(",
    ))
    request_markers = (
        "request.args",
        "request.form",
        "request.values",
        "request.json",
        "request.get_json",
        "request.user",
        "req.query",
        "req.body",
        "req.user",
    )
    route_markers = (
        "@app.route",
        "@bp.route",
        "@blueprint.route",
        "app.get(",
        "app.post(",
        "router.get(",
        "router.post(",
    )
    if not _line_has_any(lowered, route_markers):
        return False
    if not _line_has_any(lowered, request_markers):
        return False
    if _line_has_any(lowered, auth_markers) or is_auth_context_reference(lowered):
        return False
    if _line_has_any(lowered, middleware_markers) or is_auth_guard_reference(lowered):
        return False
    return language in {Language.PYTHON, Language.JAVASCRIPT, Language.TYPESCRIPT}


def detect_web_findings(parsed: ParsedDocument) -> list[Finding]:
    text = _read_text(parsed.path)
    findings: list[Finding] = []
    lines = text.splitlines()
    taint_state = build_assignment_taint_state(lines)

    if _looks_like_missing_auth_check(text, parsed.language):
        first_route_line = next(
            (
                index
                for index, line in enumerate(lines, start=1)
                if _line_has_any(
                    line,
                    (
                        "@app.route",
                        "@bp.route",
                        "@blueprint.route",
                        "app.get(",
                        "app.post(",
                        "router.get(",
                        "router.post(",
                    ),
                )
            ),
            1,
        )
        findings.append(
            _make_finding(
                AUTH_CHECK_RULE,
                path=parsed.path,
                relative_path=parsed.relative_path,
                line=first_route_line,
                evidence=lines[first_route_line - 1].strip() if lines else text.strip(),
                language=parsed.language.value,
                framework=parsed.framework,
                metadata={"auth_guard": False, "auth_model": "route_without_middleware"},
            )
        )

    if parsed.language == Language.PYTHON:
        for index, line in enumerate(lines, start=1):
            auth_guard_metadata = _auth_guard_metadata(line, parsed)
            if auth_guard_metadata:
                findings.append(
                    _make_finding(
                        AUTH_CHECK_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=auth_guard_metadata,
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                    )
                )
            if _looks_like_file_access(line, taint_state, index):
                metadata = _merge_assignment_taint_metadata(_file_access_metadata(parsed, line), line, taint_state, index)
                findings.append(
                    _make_finding(
                        FILE_ACCESS_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )
            if _looks_like_orm_query(line, taint_state, index):
                metadata = _merge_assignment_taint_metadata(_orm_query_metadata(parsed, line), line, taint_state, index)
                findings.append(
                    _make_finding(
                        ORM_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )
                continue
            if _looks_like_sql_interpolation(line, taint_state, index):
                metadata = _merge_assignment_taint_metadata(_django_flow_metadata(parsed, line, "sql_execution"), line, taint_state, index)
                findings.append(
                    _make_finding(
                        SQLI_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )
            if _line_has_any(line, ("render_template(", "render_to_string(", "get_template(", "template.render(", "jinja2.template", "template(")):
                if _has_string_escape_sanitizer(line, taint_state, index):
                    continue
                metadata = _merge_assignment_taint_metadata(_template_flow_metadata(parsed, line), line, taint_state, index)
                findings.append(
                    _make_finding(
                        TEMPLATE_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )
            if _looks_like_ssrf(line, taint_state, index):
                metadata = _merge_assignment_taint_metadata(_django_flow_metadata(parsed, line, "network_request"), line, taint_state, index)
                findings.append(
                    _make_finding(
                        SSRF_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )
            if _looks_like_path_traversal(line, taint_state, index):
                metadata = _merge_assignment_taint_metadata(_django_flow_metadata(parsed, line, "filesystem"), line, taint_state, index)
                findings.append(
                    _make_finding(
                        PATH_TRAVERSAL_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )
            if _looks_like_open_redirect(line, taint_state, index):
                metadata = _merge_assignment_taint_metadata(_django_flow_metadata(parsed, line, "redirect"), line, taint_state, index)
                findings.append(
                    _make_finding(
                        OPEN_REDIRECT_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )

    if parsed.language == Language.PHP:
        for index, line in enumerate(lines, start=1):
            if _looks_like_blade_template(line, taint_state, index):
                if _has_string_escape_sanitizer(line, taint_state, index):
                    continue
                metadata = _merge_assignment_taint_metadata(_blade_flow_metadata(parsed, lines, index), line, taint_state, index)
                findings.append(
                    _make_finding(
                        TEMPLATE_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )
            if _looks_like_laravel_process(line, taint_state):
                metadata = _merge_assignment_taint_metadata(_laravel_process_metadata(parsed, lines, index), line, taint_state, index)
                findings.append(
                    _make_finding(
                        PROCESS_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )
            if _looks_like_laravel_ssrf(line, taint_state):
                metadata = _merge_assignment_taint_metadata(_laravel_flow_metadata(parsed, lines, index, "network_request"), line, taint_state, index)
                findings.append(
                    _make_finding(
                        SSRF_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )
            if _looks_like_laravel_open_redirect(line, taint_state):
                metadata = _merge_assignment_taint_metadata(_laravel_flow_metadata(parsed, lines, index, "redirect"), line, taint_state, index)
                findings.append(
                    _make_finding(
                        OPEN_REDIRECT_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )
            if _looks_like_laravel_path_traversal(line, taint_state):
                metadata = _merge_assignment_taint_metadata(_laravel_flow_metadata(parsed, lines, index, "filesystem"), line, taint_state, index)
                findings.append(
                    _make_finding(
                        PATH_TRAVERSAL_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )
            if _looks_like_laravel_file_access(line, taint_state):
                metadata = _merge_assignment_taint_metadata(_laravel_flow_metadata(parsed, lines, index, "file_access"), line, taint_state, index)
                findings.append(
                    _make_finding(
                        FILE_ACCESS_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )

    if parsed.language in {Language.JAVA, Language.KOTLIN}:
        for index, line in enumerate(lines, start=1):
            if _looks_like_spring_deserialization(line):
                findings.append(
                    _make_finding(
                        DESERIALIZATION_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=_spring_deserialization_metadata(parsed, lines, index),
                    )
                )
            if _looks_like_spring_sql_query(line, taint_state):
                metadata = _merge_assignment_taint_metadata(_spring_flow_metadata(parsed, lines, index, "sql_query"), line, taint_state, index)
                findings.append(
                    _make_finding(
                        SQLI_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )
            if _looks_like_spring_ssrf(line, taint_state):
                metadata = _merge_assignment_taint_metadata(_spring_flow_metadata(parsed, lines, index, "network_request"), line, taint_state, index)
                findings.append(
                    _make_finding(
                        SSRF_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )
            if _looks_like_spring_open_redirect(line, taint_state):
                metadata = _merge_assignment_taint_metadata(_spring_flow_metadata(parsed, lines, index, "redirect"), line, taint_state, index)
                findings.append(
                    _make_finding(
                        OPEN_REDIRECT_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )
            if _looks_like_spring_path_traversal(line, taint_state):
                metadata = _merge_assignment_taint_metadata(_spring_flow_metadata(parsed, lines, index, "filesystem"), line, taint_state, index)
                findings.append(
                    _make_finding(
                        PATH_TRAVERSAL_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )
            if _looks_like_spring_file_access(line, taint_state):
                metadata = _merge_assignment_taint_metadata(_spring_flow_metadata(parsed, lines, index, "file_access"), line, taint_state, index)
                findings.append(
                    _make_finding(
                        FILE_ACCESS_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )

    if parsed.language in {Language.JAVASCRIPT, Language.TYPESCRIPT, Language.JSON}:
        for index, line in enumerate(lines, start=1):
            lowered = line.lower()
            auth_guard_metadata = _auth_guard_metadata(line, parsed)
            if auth_guard_metadata:
                findings.append(
                    _make_finding(
                        AUTH_CHECK_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=auth_guard_metadata,
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                    )
                )
            if _line_has_any(
                lowered,
                (
                    "render(",
                    "res.render(",
                    "response.render(",
                    "template.render(",
                    "render_to_string(",
                    "dangerouslysetinnerhtml",
                ),
            ):
                if _has_string_escape_sanitizer(line, taint_state, index):
                    continue
                metadata = _merge_assignment_taint_metadata(_template_flow_metadata(parsed, line), line, taint_state, index)
                findings.append(
                    _make_finding(
                        TEMPLATE_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )
            if "dangerouslysetinnerhtml" in lowered or "innerhtml" in lowered or "document.write" in lowered:
                if _has_string_escape_sanitizer(line, taint_state, index):
                    continue
                metadata = _merge_assignment_taint_metadata(_express_flow_metadata(parsed, line, "dom_write"), line, taint_state, index)
                metadata.update(_nextjs_flow_metadata(parsed, line, "dom_write"))
                metadata.update(_react_dom_flow_metadata(parsed, line))
                findings.append(
                    _make_finding(
                        XSS_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )
            if _line_has_any(
                lowered,
                (
                    "app.use(requireauth",
                    "router.use(requireauth",
                    "app.use(authmiddleware",
                    "router.use(authmiddleware",
                    "app.use(withauth",
                    "router.use(withauth",
                    "useauth(",
                    "withauth(",
                    "requireauth(",
                    "authmiddleware(",
                    "middlewareauth(",
                ),
            ):
                findings.append(
                    _make_finding(
                        AUTH_CHECK_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata={
                            "auth_guard": True,
                            "auth_model": "middleware",
                            "middleware_kind": "auth",
                        },
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                    )
                )
            if _looks_like_ssrf(line, taint_state, index):
                metadata = _merge_assignment_taint_metadata(_express_flow_metadata(parsed, line, "network_request"), line, taint_state, index)
                metadata.update(_nextjs_flow_metadata(parsed, line, "network_request"))
                findings.append(
                    _make_finding(
                        SSRF_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )
            if _looks_like_path_traversal(line, taint_state, index):
                metadata = _merge_assignment_taint_metadata(_express_flow_metadata(parsed, line, "filesystem"), line, taint_state, index)
                metadata.update(_nextjs_flow_metadata(parsed, line, "filesystem"))
                findings.append(
                    _make_finding(
                        PATH_TRAVERSAL_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )
            if _looks_like_open_redirect(line, taint_state, index):
                metadata = _merge_assignment_taint_metadata(_express_flow_metadata(parsed, line, "redirect"), line, taint_state, index)
                metadata.update(_nextjs_flow_metadata(parsed, line, "redirect"))
                findings.append(
                    _make_finding(
                        OPEN_REDIRECT_RULE,
                        path=parsed.path,
                        relative_path=parsed.relative_path,
                        line=index,
                        evidence=line.strip(),
                        language=parsed.language.value,
                        framework=parsed.framework,
                        metadata=metadata,
                    )
                )

    return _dedupe(findings)


def _parse_python_dependencies(text: str) -> list[tuple[str, str | None]]:
    dependencies: list[tuple[str, str | None]] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return dependencies

    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.lower() in {"install_requires", "dependencies"}:
                    if isinstance(node.value, (ast.List, ast.Tuple)):
                        for element in node.value.elts:
                            if isinstance(element, ast.Constant) and isinstance(element.value, str):
                                dependencies.append((element.value, None))
    return dependencies


def _dependency_finding_from_match(
    template: DetectorFindingTemplate,
    path: Path,
    relative_path: str,
    line: int,
    package: str,
    version: str | None,
    scope: DependencyScope,
    backend: VulnerabilityBackend,
    source_file: str,
    advisory: AdvisoryMatch,
) -> Finding:
    evidence = f"{package}=={version}" if version is not None else package
    finding = _make_finding(
        template,
        path=path,
        relative_path=relative_path,
        line=line,
        evidence=evidence,
        metadata={
            "package": package,
            "version": version,
            "dependency_scope": scope.value,
            "ecosystem": "python" if source_file.endswith(".txt") or source_file.endswith(".py") else "javascript",
            "vulnerability_backend": backend.name,
            "advisory_id": advisory.advisory_id,
            "advisory_source": advisory.source,
            "advisory_title": advisory.title,
            "advisory_description": advisory.description,
        },
        severity=advisory.severity,
    )
    return finding


def detect_dependencies(
    parsed_documents: list[ParsedDocument],
    backend: VulnerabilityBackend | None = None,
) -> list[Finding]:
    backend = backend or DEFAULT_SCA_BACKEND
    findings: list[Finding] = []
    for document in parsed_documents:
        path = document.path
        relative_path = document.relative_path.lower()
        text = _read_text(path)

        if relative_path.endswith("requirements.txt"):
            for index, line in enumerate(text.splitlines(), start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if "==" in stripped:
                    package, version = stripped.split("==", 1)
                    dependency = DependencyRecord(
                        package=package.strip(),
                        version=version.strip(),
                        source_file=document.relative_path,
                        scope=DependencyScope.DIRECT,
                        line=index,
                        ecosystem="python",
                    )
                    for advisory in backend.lookup(dependency):
                        findings.append(
                            _dependency_finding_from_match(
                                SCA_RULE,
                                path=path,
                                relative_path=document.relative_path,
                                line=index,
                                package=dependency.package,
                                version=dependency.version,
                                scope=dependency.scope,
                                backend=backend,
                                source_file=document.relative_path,
                                advisory=advisory,
                            )
                        )

        if relative_path.endswith("package.json"):
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                continue
            for section in ("dependencies", "devDependencies"):
                deps = payload.get(section, {})
                if not isinstance(deps, dict):
                    continue
                for package, version in deps.items():
                    dependency = DependencyRecord(
                        package=str(package),
                        version=str(version),
                        source_file=document.relative_path,
                        scope=DependencyScope.DIRECT,
                        line=1,
                        ecosystem="javascript",
                    )
                    for advisory in backend.lookup(dependency):
                        findings.append(
                            _dependency_finding_from_match(
                                SCA_RULE,
                                path=path,
                                relative_path=document.relative_path,
                                line=1,
                                package=dependency.package,
                                version=dependency.version,
                                scope=dependency.scope,
                                backend=backend,
                                source_file=document.relative_path,
                                advisory=advisory,
                            )
                        )

        if relative_path.endswith("package-lock.json"):
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                continue
            packages = payload.get("packages", {})
            if not isinstance(packages, dict):
                packages = {}
            for package_path, package_info in packages.items():
                if not isinstance(package_info, dict):
                    continue
                if package_path == "":
                    continue
                package_name = package_path.rsplit("node_modules/", 1)[-1]
                version = package_info.get("version")
                if not isinstance(package_name, str) or not package_name:
                    continue
                dependency = DependencyRecord(
                    package=package_name,
                    version=str(version) if version is not None else None,
                    source_file=document.relative_path,
                    scope=DependencyScope.TRANSITIVE if package_path.count("node_modules/") > 1 else DependencyScope.DIRECT,
                    line=1,
                    ecosystem="javascript",
                )
                for advisory in backend.lookup(dependency):
                    findings.append(
                        _dependency_finding_from_match(
                            SCA_RULE,
                            path=path,
                            relative_path=document.relative_path,
                            line=1,
                            package=dependency.package,
                            version=dependency.version,
                            scope=dependency.scope,
                            backend=backend,
                            source_file=document.relative_path,
                            advisory=advisory,
                        )
                    )

    return _dedupe(findings)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique[finding.id] = finding
    return list(unique.values())


def run_detectors(parsed_documents: list[ParsedDocument]) -> list[Finding]:
    findings: list[Finding] = []
    for document in parsed_documents:
        findings.extend(detect_secrets(document))
        findings.extend(detect_web_findings(document))
        findings.extend(_android_manifest_findings(document))
        findings.extend(_android_shared_preferences_findings(document))
    findings.extend(detect_dependencies(parsed_documents))
    return _dedupe(findings)
