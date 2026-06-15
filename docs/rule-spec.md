# Rule Spec

## Purpose
Rules define how the scanner finds security issues and how each finding is described, scored, and mapped to standards.

## Rule Model
Each rule has:
- id
- name
- description
- category
- severity
- confidence
- strategy
- target languages
- optional target frameworks
- OWASP mapping
- CWE mapping
- patterns or taint logic
- remediation text
- examples
- metadata

## Rule Categories
- secrets
- sca
- injection
- xss
- ssrf
- access_control
- authentication
- deserialization
- path_traversal
- file_access
- process_execution
- open_redirect
- crypto
- configuration
- mobile
- custom

## Matching Strategies
- `pattern`
- `taint`
- `sca`
- `metadata`
- `custom`

## Rule Pack Format
Rule packs are stored as TOML for the MVP.

Reasons:
- Python can read TOML with the standard library.
- The format stays human-editable.
- The schema is explicit and versionable.

## Rule Pack Contract
- Pack name and version are required.
- Every rule must have a stable id.
- Every rule must have exactly one primary category.
- Severity and confidence must be valid enum values.
- Unsupported fields should fail validation unless explicitly namespaced under `metadata`.
- A pack may contain zero or more rules, but a built-in pack should contain at least one rule.

## TOML Shape
```toml
name = "builtin"
version = "0.1.0"

[[rules]]
id = "SEC-SECRET-001"
name = "Hardcoded Secret"
description = "Detects obvious hardcoded secret material."
category = "secrets"
severity = "high"
confidence = "medium"
strategy = "pattern"
owasp = ["A05:2021 - Security Misconfiguration"]
cwe = ["CWE-798"]
remediation = "Move secrets out of source control."

[[rules.targets]]
language = "python"

[[rules.patterns]]
kind = "regex"
value = "(?i)(api[_-]?key|secret|token|password)\\s*[:=]"
```

## Validation Rules
- `id`, `name`, `description`, `category`, `severity`, `confidence`, and `strategy` are required.
- `targets`, `owasp`, `cwe`, `patterns`, `examples`, and `metadata` are optional.
- `targets` entries must include a language.
- `patterns` entries must include a kind and value.
- `metadata` must be a TOML table if present.
- Invalid enum values must fail pack loading early.

## Built-In Pack Requirements
- The first built-in pack must cover at least:
  - one secrets rule
  - one raw SQL injection rule
  - one DOM XSS rule
- The built-in pack must have stable identifiers.
- Rule ids must remain stable once the pack ships.

## Custom Pack Requirements
- Custom packs may add organization-specific rules.
- Custom packs must not break loading of the built-in pack.
- Custom packs must use the same field names as built-in packs.
- Custom packs should be usable without CLI code changes.

## Example Extended Rule
```toml
[[rules]]
id = "WEB-XSS-001"
name = "DOM XSS"
description = "Detects unsafe DOM sinks with attacker-controlled content."
category = "xss"
severity = "high"
confidence = "medium"
strategy = "pattern"
owasp = ["A03:2021 - Injection"]
cwe = ["CWE-79"]
remediation = "Use safe DOM APIs or output encoding."
examples = ["element.innerHTML = userInput"]

[[rules.targets]]
language = "javascript"
framework = "react"

[[rules.targets]]
language = "typescript"
framework = "nextjs"

[[rules.patterns]]
kind = "regex"
value = "innerHTML\\s*=\\s*"
description = "Direct assignment to a DOM HTML sink."
```

## Scoring Rules
- Severity describes impact.
- Confidence describes certainty.
- A rule can be high severity with medium confidence.
- Policy gates use severity first, then confidence if needed.

## Finding Mapping Rules
- One rule can create multiple findings.
- Every finding must reference one rule id.
- Every finding must include a stable location.
- Evidence is optional but strongly preferred.

## Suppression Policy
- Suppressions are allowed only with a reason.
- Suppressions must be audit-friendly.
- Baseline entries are not the same as suppressions.

## Custom Rules
- Custom rules must use the same schema as built-in rules.
- Custom rules must be validated before loading.
- Custom rules should not require code changes in the CLI.
- Custom rules should be versioned and reviewed like code.
