# Rust Workspace

This workspace is reserved for the compute-heavy analysis core.

## Intended Scope

- parser adapters
- IR normalization
- taint/dataflow engine
- performance-sensitive rule evaluation

The Python CLI is expected to call into this layer later, but the first release stays Python-first.

