# MoSec Foundation Pack

## Purpose
This document package defines the first implementation contract for the MoSec CLI project. It is the bridge between product planning and concrete implementation.

## The Seven Artifacts
1. `docs/mvp-spec.md`
2. `docs/cli-contract.md`
3. `docs/rule-spec.md`
4. `docs/test-strategy.md`
5. `fixtures/`
6. `docs/adrs/`
7. `docs/data-schema.md`

## Working Order
1. MVP spec
2. CLI contract
3. Rule spec
4. Data schema
5. Test strategy
6. Fixture corpus
7. ADRs

## Output Of This Pack
- A narrow MVP scope for the first CLI release.
- A stable command contract.
- A rule and finding model that can survive future Rust extraction.
- A fixture-driven test base.
- A small set of recorded architecture decisions.

## Done When
- The MVP is narrow enough to implement without scope creep.
- The CLI contract matches the current code skeleton.
- Rules, findings, and report artifacts share one schema vocabulary.
- Fixtures exist for every first-class detection category.
- The core ADRs are written down and referenced by the roadmap.
