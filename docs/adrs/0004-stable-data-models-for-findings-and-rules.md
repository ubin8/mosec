# ADR 0004: Stable Data Models For Findings And Rules

## Status
accepted

## Context
The scanner needs a durable internal contract so rules, findings, and reports do not drift as the codebase grows.

## Decision
- Define explicit model objects for findings, rules, and scan results.
- Keep severity and confidence separate.
- Store location, evidence, metadata, and mappings as first-class data.

## Consequences
- Easier serialization to JSON and SARIF.
- Easier fixture testing.
- Easier Rust porting later because the schema is explicit.

