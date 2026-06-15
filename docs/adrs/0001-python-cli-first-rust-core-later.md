# ADR 0001: Python CLI First, Rust Core Later

## Status
accepted

## Context
We need a first release that is fast to build and easy to change. The scanner needs to cover CLI orchestration, config handling, reporting, and early rule logic before any performance-critical work becomes necessary.

## Decision
- The CLI and product orchestration are implemented in Python first.
- Rust is reserved for later parser, IR, or taint-heavy components.
- The public CLI contract does not depend on Rust being present.

## Consequences
- Faster path to a usable MVP.
- Easier rule and report iteration.
- Rust can be introduced only where it provides clear value.
- The Python layer must stay structured enough to hand off hot paths later.

