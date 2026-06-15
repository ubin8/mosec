# ADR 0006: Fixture-Driven Scanner Development

## Status
accepted

## Context
The scanner will evolve through rules and detectors. Without deterministic fixtures, regressions will be hard to catch.

## Decision
- Build the scanner against a small but explicit fixture corpus.
- Pair positive and negative examples for each detection class.
- Use fixtures for golden output and regression validation.

## Consequences
- Rule changes become easier to review.
- False positives and regressions are easier to spot.
- The test suite can grow with the product.

