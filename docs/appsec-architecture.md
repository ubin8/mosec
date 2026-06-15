# MoSec Analysis Platform Architecture

## Ziel
Eine gemeinsame Architektur fuer statische Sicherheitsanalyse, die sprach- und framework-aware ist, Findings normalisiert und verschiedene Ausgabe- und Integrationskanaele bedienen kann.

## Grundprinzipien
- Eine Quelle der Wahrheit fuer Findings.
- Analyse und Ausgabe muessen entkoppelt sein.
- Regeln sollen als Daten oder kleine Module ladbar sein.
- Jede Analyse muss reproduzierbar sein.
- Kontext muss bis zum Report erhalten bleiben.

## Ziel-Stack
### Eingaben
- Source Code Repositories
- Lockfiles und Package-Manifeste
- Mobile Artefakte und Konfigurationen
- IaC-Dateien
- CI-Konfigurationen

### Kernmodule
1. Code Ingestion
2. Language Detection
3. Parser / AST
4. Intermediate Representation
5. Rule Engine
6. Dataflow / Taint Analysis
7. Framework Adapters
8. Dependency / Secrets / Config Checks
9. Risk Scoring
10. Remediation Engine
11. Reporting / Integrations

## Architekturfluss
```text
Repository Ingestion
  -> File Selection
  -> Language / Framework Detection
  -> Parse Layer
  -> AST / IR Normalization
  -> Rule Matching
  -> Dataflow / Taint Propagation
  -> Reachability / Control-Flow Checks
  -> Finding Normalization
  -> Scoring
  -> Remediation Suggestions
  -> Export / CI / PR / API
```

## Kernmodelle
### Finding
Ein Finding braucht mindestens:
- stabile ID
- Rule ID
- Severity
- Confidence
- Sprache
- Framework
- Pfad und Zeilenbereich
- evidenzbasierten Codeausschnitt
- erklaerenden Titel
- technische Begruendung
- Remediation-Hinweis
- Baseline- und Suppression-Metadaten

### Rule
Eine Rule braucht mindestens:
- Rule ID
- Name
- Kategorie
- Standards-Mapping zu OWASP und CWE
- Zielsprachen
- Schweregrad
- Confidence-Vorgabe
- Matching- oder Taint-Strategie
- Beispielcode
- False-Positive-Hinweis

### Analysis Context
Der Kontext sollte enthalten:
- Sprache
- Framework
- Entry Points
- Known Sources
- Known Sinks
- Sanitisers
- Repository-Metadaten
- Scan-Parameter
- Baseline-Referenz

## Module im Detail
### Ingestion Layer
- Erkennt Repository-Struktur.
- Nimmt Excludes und Includes entgegen.
- Normalisiert Dateipfade.
- Filtert Binaerdateien und generierte Artefakte.
- Folge-Symlinks werden im Traversal nicht betreten; ein symlinkierter Scan-Root wird aufgeloest und gemeldet.
- Erzeugt Scan-Work-Units.

### Parser / AST / IR
- Parsen pro Sprache kapseln.
- Sprache mit bestmoeglichem Parser behandeln.
- AST in eine gemeinsame IR ueberfuehren.
- Die minimale IR umfasst Calls, Assignments, Literale und Member-Zugriffe.
- Codeausschnitte und Symbolinformationen mitnehmen.
- Fehlerhafte Dateien isoliert behandeln statt den Scan abzubrechen.

### Rule Engine
- Statische Pattern-Regeln.
- Kontextbasierte Regeln.
- Taint-basierte Regeln.
- Framework-spezifische Spezialregeln.
- Konfigurierbare Severity- und Confidence-Defaults.

### Dataflow / Taint Analysis
- Sources markieren.
- Propagation ueber Assignments, Calls und Returns verfolgen.
- Sinks erkennen.
- Sanitisers und Guards modellieren.
- Pfadinformationen speichern.
- Merges und Branches konservativ behandeln.

### Framework Adapters
- Express und Next.js fuer Node.
- Django und Python-Web-Frameworks.
- Laravel und PHP.
- Spring und Java/Kotlin.
- React Native und mobile JS-Stacks.
- Flutter und Dart.
- Android und iOS spezifische Metadaten.

### Dependency / Secrets / Config Checks
- Lockfiles und Manifestdateien lesen.
- CVE- und Paketdaten verknuepfen.
- Secret-Muster gegen Kontext validieren.
- IaC-Fehler separat bewerten.
- Konfigurationsrisiken mit hoher Prioritaet behandeln.

### Risk Scoring
- Severity und Confidence getrennt halten.
- Reachability und Exploitability als Zusatzsignale modellieren.
- Baseline-Status als Filter verwenden.
- Policy Gates ueber Score und Schweregrad steuern.

### Remediation Engine
- Konkrete Fix-Hinweise pro Finding generieren.
- Sicheres Minimal-Pattern anbieten.
- Framework-konforme Remediation bevorzugen.
- Hinweise auf Tests oder Verifikationsschritte geben.

### Reporting / Integrations
- JSON als Maschinenformat.
- SARIF fuer Security-Tools und Code-Hosts.
- HTML fuer lesbare Reviews.
- API fuer Dashboards und Automatisierung.
- PR-Kommentare mit Line-Precision.

## Vorschlag fuer Ziel-Repo-Struktur
```text
src/
  core/
  ingestion/
  parsing/
  ir/
  rules/
  taint/
  framework/
  secrets/
  sca/
  reporting/
  integrations/
  cli/
docs/
```

## Nicht-funktionale Anforderungen
- Reproduzierbare Scans
- Gute Performance auf grossen Repositories
- Isolierte Fehlertoleranz pro Datei
- Geringes Noise-Level
- Auditierbare Suppressions
- Erweiterbarkeit ohne komplette Rewrites

## Architektur-Entscheidungen, die frueh festgezurrt werden muessen
- Primaere Parsing-Strategie pro Sprache
- Form der Rule-Definition
- Form der IR
- Speicherstrategie fuer Findings und Pfade
- Baseline-Match-Strategie
- Policy-Engine fuer Blocker-Entscheidungen
