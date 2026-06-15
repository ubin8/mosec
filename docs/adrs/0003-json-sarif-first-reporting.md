# ADR 0003: JSON, Text, and SARIF as First Output Formats

## Status
accepted

## Context
The tool needs outputs for both humans and automation.

## Decision
- Text is the developer-friendly local output.
- JSON is the canonical machine format.
- SARIF is the CI and code-host export format.

## Consequences
- One data model can back all output formats.
- Reports are easier to test with golden files.
- Future HTML or API outputs can derive from the same schema.

