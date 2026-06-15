# Rules and Findings

## Rule packs

Rules are loaded from TOML files.

Each rule contains:

- id
- name
- description
- category
- severity
- confidence
- strategy
- targets
- OWASP mapping
- CWE mapping
- patterns
- remediation
- examples
- metadata

## Finding fields

Findings carry:

- id
- rule_id
- title
- message
- severity
- confidence
- location
- category
- language
- framework
- evidence
- remediation
- status
- triage metadata
- symbols
- custom metadata

## Severity and confidence

- Severity describes impact.
- Confidence describes certainty.
- They are independent.

## Baselines, suppressions, and overrides

- Baselines hide already-known findings.
- Suppressions hide accepted findings and require a reason.
- Manual overrides let a reviewer force a finding active or suppressed for a bounded scope.

## Current rule families

- Secrets
- SCA
- Injection
- XSS
- SSRF
- Path traversal
- Open redirect
- Auth checks
- Template injection
- Deserialization
- File access
- Process execution
- Mobile / Android

