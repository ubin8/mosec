# Data Schema

## Purpose
Define the shared data vocabulary for findings, rules, scan runs, suppressions, baselines, and exports.

## Entities
### ScanRun
- `id`: stable run id
- `root`: scanned path
- `started_at`
- `finished_at`
- `tool_version`
- `config_ref`
- `stats`
- `notes`
- `audit_log`
- `rule_packs`

### Finding
- `id`
- `rule_id`
- `title`
- `message`
- `severity`
- `confidence`
- `status`
- `triage_status`
- `triage_reason`
- `triage_note`
- `category`
- `language`
- `framework`
- `location`
- `evidence`
- `owasp`
- `cwe`
- `remediation`
- `tags`
- `symbols`
- `metadata`

### ParsedDocument
- `path`
- `relative_path`
- `language`
- `framework`
- `syntax_valid`
- `line_count`
- `character_count`
- `ir`
- `issues`
- `metadata`
- `metadata` may include parsed artifact-specific objects such as `android_manifest` for `AndroidManifest.xml`.

### IRDocument
- `path`
- `nodes`
- `metadata`

### SourceKind
- `query`
- `body`
- `headers`
- `cookies`
- `path`
- `form`
- `request_input`
- `search_params`
- `route_param`
- `auth_context`

### SourceMarkers
- Query markers map request/query-string style inputs to `query` or `search_params` source kinds.
- Body markers map request payload accessors and deserialization entry points to `body` source kind.
- Cookie markers map request cookie accessors to `cookies` source kind.
- Auth-context markers map authenticated principal/session accessors to `auth_context` source kind.
- Auth-guard markers map decorators and middleware names to a protected-route signal.
- Auth-guard metadata may use `auth_guard_kind = auth_check` plus `auth_model = decorator|middleware|predicate` for route protection findings.
- Role-guard markers map RBAC helpers such as `hasRole`, `can`, and `authorize` to `auth_model = role_check`.
- Body sources should cover raw request bodies, JSON payload parsing, form payload parsing, and framework-specific body readers.
- Query sources should be treated as user-input sources for taint starts.

### TaintMetadata
- `taint_propagation`: currently `assignment`, `function_call`, `return_value`, `container`, or `field`.
- `tainted_variables`: list of variable names participating in the propagated flow.
- `taint_source_kind`: root source kind for the tainted chain.
- `taint_source_expression`: direct source expression that introduced the taint.
- `taint_source_line`: source line where the taint originated.
- `taint_origin_variable`: first alias variable if the flow was propagated.
- `taint_call`: helper function name when propagation crossed a same-file function call or returned through one.
- `taint_sanitized`: boolean indicating that the propagated taint passed through a sanitizer before reaching the sink line.
- `taint_sanitizer_kind`: normalized sanitizer family such as `html_escape`.
- `taint_sanitizer_call`: concrete sanitizer call name such as `html.escape` or `escapeHtml`.
- `taint_guarded`: boolean indicating that the flow is protected by a URL allowlist guard.
- `taint_guard_kind`: normalized guard family such as `url_allowlist`.
- `taint_guard_call`: concrete guard call or guard expression.
- `taint_guard_line`: line number of the allowlist guard when known.
- `taint_reachability`: `reachable`, `unreachable`, or `unknown`.
- `taint_path`: ordered list of path steps from source to sink.
- `taint_sink_line`: sink line number for the current finding.
- `taint_exploitability_context`: compact object with reachability, source, sink, branch, and guard context.
- `taint_branch_context`: boolean indicating that the tainted lineage originated in a conditional branch.
- `taint_branch_kind`: branch type such as `if`, `elif`, or `else`.
- `taint_branch_line`: branch header line that introduced the conservative branch context.
- `taint_chain`: ordered list of aliases from origin to sink variable.

### AndroidManifestMetadata
- `package`
- `shared_user_id`
- `uses_permissions`
- `uses_features`
- `application`
- `components`
- `application.debuggable`
- `application.allow_backup`
- `application.uses_cleartext_traffic`
- `components[].kind`
- `components[].name`
- `components[].exported`
- `components[].permission`
- `components[].intent_filter_count`
- `uses_permissions` includes declared permissions from `uses-permission` and SDK-specific permission tags.
- Dangerous-permission findings may carry `permission_name`, `permission_risk`, `manifest_kind = permission`, and `android_package` metadata.

### AndroidSharedPreferencesFindingMetadata
- `storage_kind`
- `storage_risk`
- `shared_preferences_mode`
- `shared_preferences_key`
- `manifest_kind = storage`
- `android_package`

### RulePack
- `name`
- `version`
- `rules`
- `metadata`

### Rule
- `id`
- `name`
- `description`
- `category`
- `severity`
- `confidence`
- `strategy`
- `targets`
- `owasp`
- `cwe`
- `patterns`
- `remediation`
- `examples`
- `metadata`

### BaselineEntry
- `rule_id`
- `path`
- `start_line`
- `fingerprint`
- `reason`
- `created_at`

### Suppression
- `target`
- `reason`
- `author`
- `created_at`
- `expires_at`
- `scope`
- `review_status`
- `reviewed_by`
- `reviewed_at`
- `review_note`

### ManualOverride
- `target`
- `decision`
- `reason`
- `author`
- `created_at`
- `expires_at`
- `scope`

### ReportArtifact
- `format`
- `path`
- `generated_at`
- `scan_run_id`

### AuditEntry
- `action`
- `subject_type`
- `subject_id`
- `decision`
- `reason`
- `actor`
- `created_at`
- `metadata`

## Field Rules
- Identifiers must be stable across repeated scans.
- Locations must use file path plus line numbers.
- Severity and confidence are separate fields.
- Evidence should be textual, not binary.
- Metadata is reserved for format-specific extensions.
- Schemas should be forward-compatible by addition, not by renaming.

## Canonical Field Types
- `id`: stable string
- `path`: repository-relative or normalized absolute string
- `severity`: enum string
- `confidence`: enum string
- `decision`: enum string
- `status`: enum string
- `triage_status`: enum string
- `triage_reason`: free-form string or null
- `triage_note`: free-form string or null
- `review_status`: enum string
- `reviewed_by`: free-form string or null
- `reviewed_at`: RFC 3339 timestamp string or null
- `review_note`: free-form string or null
- `created_at`: RFC 3339 timestamp string
- `location`: nested object with path and line numbers
- `ir`: compact, language-specific intermediate representation
- `rule_packs`: list of loaded rule packs with versions
- `audit_log`: list of audit entries
- `metadata`: arbitrary object reserved for extensions

## Example Shapes
### Finding
```json
{
  "id": "finding-1",
  "rule_id": "SEC-SECRET-001",
  "title": "Hardcoded Secret",
  "message": "Detects obvious hardcoded secret material.",
  "severity": "high",
  "confidence": "medium",
  "status": "new",
  "triage_status": "untriaged",
  "triage_reason": null,
  "triage_note": null,
  "category": "secrets",
  "language": "python",
  "framework": null,
  "location": {
    "path": "src/app.py",
    "start_line": 12,
    "start_column": 1,
    "end_line": 12,
    "end_column": null
  },
  "symbols": [
    {
      "name": "user_input",
      "kind": "parameter",
      "qualified_name": "handler.user_input",
      "line": 12
    }
  ]
}
```

### Rule
```json
{
  "id": "SEC-SECRET-001",
  "name": "Hardcoded Secret",
  "description": "Detects obvious hardcoded secret material.",
  "category": "secrets",
  "severity": "high",
  "confidence": "medium",
  "strategy": "pattern"
}
```

### ParsedDocument
```json
{
  "path": "src/app.py",
  "relative_path": "src/app.py",
  "language": "python",
  "framework": "flask",
  "syntax_valid": true,
  "line_count": 120,
  "character_count": 4120,
  "ir": {
    "path": "src/app.py",
    "nodes": [
      {
        "kind": "assignment",
        "target": "query",
        "value": "db.client.execute(user_input)"
      }
    ]
  }
}
```

## Serialization Rules
- JSON is the canonical machine format.
- SARIF is an export format derived from the schema.
- Text output is a presentation layer, not a schema source.
- JSON field names should map directly to the Python model objects.
- SARIF output should be derived from JSON-like internal objects, not hand-built ad hoc.

## Compatibility Rules
- New fields can be added.
- Existing field names should not change casually.
- Schema migrations must be documented in an ADR.
- Breaking changes require a versioned migration path.
