# MoSec Analysis Platform Roadmap

## Zielbild
MoSec ist eine Analysis Platform fuer Web- und Mobile-Anwendungen, die statische Analyse, SCA, Secrets-Scanning, Policy Gates, PR-Kommentare und spaeter auch fortgeschrittene Analyseformen in einer gemeinsamen Plattform zusammenfuehrt.

## Leitplanken
- Fokus zuerst auf ein belastbares MVP, dann auf Breite und Tiefe.
- SAST ist der Kern, aber nicht das ganze Produkt.
- Jede Funktion muss als direktes, nachvollziehbares Finding mit Kontext auslieferbar sein.
- Rules, Findings, Suppressions und Reports muessen auditierbar sein.
- Jede neue Analyseart muss auf die gleiche Kernpipeline aufsetzen.

## Produktgrenzen
### In Scope
- CLI Scanner fuer Repositories
- Web- und Mobile-Codeanalyse
- Secrets-Scanning
- Dependency-Analyse / SCA
- OWASP Top 10, CWE und relevante Mobile-Bedrohungen
- Dataflow- und Taint-Analyse
- Baseline-Modus
- False-Positive-Management
- SARIF, JSON und menschenlesbare Reports
- GitHub- und GitLab-Integration
- PR-Kommentare und Policy Gates

### Out of Scope fuer das erste MVP
- Vollstaendige DAST-Engine
- Vollstaendige MAST-Engine
- Vollautomatische Exploit-Erstellung
- Vollstaendige Auto-Fix-Konvertierung ohne Review
- Breite Enterprise-Integrationen wie Jira oder SIEM

## Prioritaeten
| Prioritaet | Inhalt |
| --- | --- |
| P0 | Kernscanner, Regeln, Secrets, SCA, SARIF, Baseline, Suppressions |
| P1 | CI/CD, PR-Kommentare, Policy Gates, bessere Remediation, Framework-Awareness |
| P2 | Mobile-Checks, Dashboard, API, Team- und Audit-Funktionen |
| P3 | Reachability, Exploitability, AI-Assist, Jira/Linear, IDE-Integrationen |

## Meilensteine
### M0 - Produkt und Architektur festziehen
- [x] Produktname und Positionierung festlegen.
- [x] Zielkunden und Use Cases definieren.
- [x] Nicht-Ziele schriftlich abgrenzen.
- [x] Prioritaeten P0 bis P3 final bestaetigen.
- [x] Zielsprachen fuer das erste Release festlegen.
- [x] Ziel-Frameworks fuer das erste Release festlegen.
- [x] Ziel-Reportformate festlegen.
- [x] Richtlinie fuer Findings, Severity-Werte und CWE-Mapping definieren.
- [x] Richtlinie fuer Suppressions und Baseline definieren.

### M1 - Kernpipeline laeuft
- [x] Repository-Ingestion implementieren.
- [x] Datei-Discovery und Excludes definieren.
- [x] Parser-Auswahl pro Sprache festlegen.
- [x] AST- oder IR-Schicht definieren.
- [x] Einheitliches Finding-Modell definieren.
- [x] Einheitliches Rule-Modell definieren.
- [x] Result-Writer fuer JSON und SARIF bauen.
- [x] Minimalen CLI-Workflow implementieren.

### M2 - Erste Sicherheitswerte liefern
- [x] Secrets-Scanner einfuehren.
- [x] Dependency-Scanner einfuehren.
- [x] Erste OWASP-Regeleintraege ausliefern.
- [x] Erste CWE-Mappings ausliefern.
- [x] Baseline-Modus integrieren.
- [x] Suppressions mit Audit-Trail integrieren.
- [x] Remediation-Hinweise im Finding-Kontext anzeigen.

### M3 - CI und Pull-Request-Workflow
- [ ] GitHub Actions Integration.
- [ ] GitLab CI Integration.
- [ ] PR-Kommentare mit Diffs und Kontext.
- [x] Policy Gates fuer Critical und High.
- [x] CLI Exit-Codes an Policy koppeln.
- [ ] Scan-Ergebnisse als Artefakte exportieren.

### M4 - Framework- und Datenflussanalyse
- [ ] Framework-Erkennung implementieren.
- [ ] Sanitisers und Sources modellieren.
- [ ] Sinks und dangerous APIs modellieren.
- [ ] Taint-Propagation implementieren.
- [ ] Control-Flow-relevante Reachability einfuehren.
- [ ] Framework-spezifische Regeln priorisieren.

### M5 - Mobile-Analyse
- [ ] Android-spezifische Regeln einfuehren.
- [ ] iOS-spezifische Regeln einfuehren.
- [ ] WebView- und IPC-Risiken analysieren.
- [ ] Manifest- und Entitlements-Checks einbauen.
- [ ] Mobile-Sensitive-Storage-Checks einfuehren.

### M6 - Plattform und Betrieb
- [ ] Dashboard fuer Projekte und Trends.
- [ ] API fuer Scans und Findings.
- [ ] Audit-Log fuer Suppressions und Freigaben.
- [ ] Team- und Projektmodelle.
- [ ] Rollen und Zugriffssteuerung.

### M7 - Advanced Features
- [ ] Reachability-Scoring ausbauen.
- [ ] Exploitability-Scoring pruefen.
- [ ] AI-gestuetzte Remediation testen.
- [ ] Attack-Path-Analyse evaluieren.
- [ ] SBOM-Export integrieren.
- [ ] Jira/Linear-Integration evaluieren.

## Roadmap nach Arbeitsstroemen
### 1. Produktdefinition
- [x] Problemstatement in 1 Absatz formulieren.
- [x] Zielgruppe in 3 Segmenten beschreiben.
- [x] Wettbewerb und Differenzierung festhalten.
- [x] Messbare Erfolgsmetriken definieren.

### 2. Analyse-Kern
- [x] Parser-Pipeline standardisieren.
- [x] Rule-DSL oder Rule-API entwerfen.
- [x] Findings-Schema festlegen.
- [x] Context-Carrying fuer Codeausschnitte definieren.
- [x] Severity- und Confidence-Modell festlegen.

### 3. Erste Detektionen
- [x] Secrets-Regeln priorisieren.
- [x] Dependency-Regeln priorisieren.
- [x] Injection-Regeln priorisieren.
- [x] XSS-Regeln priorisieren.
- [ ] SSRF-Regeln priorisieren.
- [ ] Access-Control-Regeln priorisieren.

### 4. Integrationen
- [x] CLI-Flags und Exit-Codes definieren.
- [ ] CI-Templates vorsehen.
- [x] SARIF-Schema validieren.
- [ ] PR-Kommentierlogik definieren.
- [x] Baseline- und Suppression-Workflow dokumentieren.

### 5. Plattform
- [ ] Projektmodell entwerfen.
- [ ] Scan-Historie speichern.
- [ ] Trends pro Projekt und Team ableiten.
- [ ] Auditierbarkeit pro Finding sicherstellen.

### 6. Erweiterung
- [ ] Mobile-Analyse erweitern.
- [ ] IaC-Checks als eigene Packung vorsehen.
- [ ] Container-Checks separat bewerten.
- [ ] DAST/MAST als spaetere Produkte ausweisen.

## Definition of Done fuer die Roadmap
- [x] Jedes P0-Item ist in kleine Tasks zerlegt.
- [x] Die Reihenfolge ist implementierbar ohne Rueckspruenge.
- [x] Die Dokumente koennen als Arbeitsgrundlage fuer Planung und Tracking dienen.
- [x] Die Roadmap deckt Web, Mobile, Plattform und Integrationen ab.
