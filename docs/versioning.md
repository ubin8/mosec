# MoSec Versioning

## Purpose
Define how the CLI and rule packs are versioned so reports, fixtures, and integrations stay predictable.

## CLI Versioning
- MoSec follows semantic versioning for the CLI package.
- A CLI release changes the major version when the command contract or report schema breaks compatibility.
- Minor releases may add flags, rules, or detectors without breaking existing output contracts.
- Patch releases fix bugs without changing the public contract.

## Rule Pack Versioning
- Rule packs use semantic versioning independently from the CLI.
- A rule pack version changes when rule IDs, mappings, severities, or remediation behavior changes in a user-visible way.
- Rule pack metadata must include `name` and `version`.
- Reports should surface the rule pack version when a scan is executed with a loaded pack.

## Compatibility Rules
- A CLI release should be able to load rule packs from the same major line.
- Test fixtures should pin both CLI output expectations and rule pack versions.
- If a rule pack changes behavior, the change must be reflected in the changelog or a dedicated release note.
