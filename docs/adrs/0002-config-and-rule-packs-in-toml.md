# ADR 0002: TOML For Config And Rule Packs

## Status
accepted

## Context
We need a format that is easy to read, easy to version, and available in Python without extra runtime complexity.

## Decision
- Use TOML for CLI configuration.
- Use TOML for MVP rule packs.
- Keep the schema explicit and versioned.

## Consequences
- No YAML dependency for the first release.
- Config and rule files can be parsed with standard-library support.
- Schema evolution needs versioning discipline.

