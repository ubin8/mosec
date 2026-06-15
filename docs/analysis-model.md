# Analysis Model

MoSec follows a simple pipeline:

1. File ingestion
2. Language and framework classification
3. Parsing and normalization
4. Detection
5. Workflow filtering
6. Reporting

## Current building blocks

- Repository ingestion and file discovery
- Python, JavaScript, TypeScript, Java, Kotlin, PHP, JSON, TOML, and XML handling
- Structured parsing and a small IR for calls, assignments, literals, and member access
- Rule-based detection for secrets, SCA, and common web issues
- Taint propagation for assignment, function calls, returns, containers, fields, and reachability context

## Framework awareness

Current framework support includes:

- Flask
- Django
- FastAPI
- Express
- Next.js
- React
- Spring
- Laravel
- Android

## Why the IR is small

The IR is intentionally compact so it can:

- support pattern rules today
- grow into deeper analysis later
- remain stable across languages
- stay easy to serialize and test

## Data flow concepts

MoSec models:

- user input sources
- sanitizers
- guards
- sinks
- reachability
- branch context

This lets MoSec explain why a finding exists and how far the flow traveled, whether the analysis was started from the CLI or through a TUI command.
