# MoSec Analysis Platform Backlog

## Nutzung
- Jeder Punkt ist bewusst klein gehalten.
- `[ ]` bedeutet offen, `[x]` bedeutet erledigt.
- Reihenfolge ist wichtig: erst Kernel, dann Analyse, dann Integrationen, dann Plattform.
- Fuer die technische P0-Zerlegung siehe [appsec-p0-backlog.md](/home/lucas/MO/docs/appsec-p0-backlog.md).

## P0 - Fundament
### Produkt und Scope
- [x] Produktziel in einem Satz festziehen.
- [x] Zielkunden in 3 Hauptgruppen benennen.
- [x] Primare Use Cases in Prioritaetsreihenfolge festhalten.
- [x] Nicht-Ziele fuer das MVP schriftlich fixieren.
- [x] Erste Zielsprachen fuer das MVP festlegen.
- [x] Erste Ziel-Frameworks fuer das MVP festlegen.
- [x] Erwartete Reportformate festlegen.
- [x] Datenhaltung fuer Findings und Scans grob festlegen.

### Repository-Ingestion
- [x] CLI Entry Point anlegen.
- [x] Repositories lokal einlesen koennen.
- [x] Einzelne Dateien scanbar machen.
- [x] Include- und Exclude-Listen unterstuetzen.
- [x] Generierte Dateien ausschliessen.
- [x] Binaerdateien aussortieren.
- [x] Pfade normalisieren.
- [x] Scan-Units erzeugen.

### Sprach- und Framework-Erkennung
- [x] Sprache pro Datei erkennen.
- [x] Lockfiles erkennen.
- [x] Framework-Hinweise aus Ordnerstruktur erkennen.
- [x] Package-Manifeste erkennen.
- [x] Mobile-Metadaten erkennen.
- [x] Erkennungsfehler als nicht-fatal behandeln.

### Parser-Schicht
- [x] Parser-Interface definieren.
- [x] Syntaxfehler pro Datei isolieren.
- [x] Parser-Fehler als Finding oder Diagnostic reporten.
- [x] Codeausschnitte mit Zeilennummern speichern.
- [x] Symbolreferenzen mitgeben, wenn moeglich.
- [x] Parser-Auswahl pro Sprache konfigurierbar machen.

### IR und Normalisierung
- [x] Gemeinsames Finding-Schema festlegen.
- [x] Gemeinsames Code-Location-Schema festlegen.
- [x] Gemeinsames Symbol-Schema festlegen.
- [x] Einfache IR fuer Calls und Assignments definieren.
- [x] Relevante Literale in der IR erhalten.
- [x] Normalisierung fuer mehrere Sprachen festlegen.

### Rule-Modell
- [x] Rule-ID-Konvention definieren.
- [x] Rule-Kategorien definieren.
- [x] Severity-Matrix definieren.
- [x] Confidence-Matrix definieren.
- [x] OWASP-Mapping-Format definieren.
- [x] CWE-Mapping-Format definieren.
- [x] Rule-Metadaten-Schema definieren.
- [x] Beispielcode pro Rule vorsehen.

### Reporting
- [x] JSON-Export definieren.
- [x] SARIF-Export definieren.
- [x] Lesbaren Textreport definieren.
- [x] Report-Header mit Scan-Metadaten definieren.
- [x] Report-Ordering nach Schweregrad definieren.
- [x] Deduplizierung von Findings definieren.

## P0 - Erste Detektionen
### Secrets
- [x] API-Key-Pattern definieren.
- [x] Token-Pattern definieren.
- [x] Private-Key-Pattern definieren.
- [x] Hardcoded-Passwort-Pattern definieren.
- [x] Kontextpruefung gegen False Positives einbauen.
- [x] Whitelisting fuer Testdaten vorsehen.

### Dependency / SCA
- [x] Package-Lockfiles lesen.
- [x] Manifestdateien lesen.
- [x] Paketnamen und Versionen extrahieren.
- [x] CVE-Quelle als austauschbares Backend vorsehen.
- [x] Schweregrade aus Vulnerability-Daten uebernehmen.
- [x] Direkt- und Transitiv-Abhaengigkeiten unterscheiden.

### Basis-SAST fuer Web
- [x] Injection-Sink-Mapping definieren.
- [x] XSS-Sink-Mapping definieren.
- [x] SSRF-Sink-Mapping definieren.
- [x] Path-Traversal-Sink-Mapping definieren.
- [x] Open-Redirect-Sink-Mapping definieren.
- [x] Auth-Check-Regeln als eigene Gruppe definieren.

### Baseline und Suppressions
- [x] Baseline-Dateiformat festlegen.
- [x] Existing-Findings mit Baseline abgleichen.
- [x] Neue Findings von bestehenden Findings unterscheiden.
- [x] Suppression-Kommentarformat definieren.
- [x] Suppression-Gruende verpflichtend machen.
- [x] Suppressions im Audit-Trail speichern.

## P1 - CI/CD und Collaboration
### CLI und Exit-Verhalten
- [x] Exit-Code fuer clean scan definieren.
- [x] Exit-Code fuer policy violation definieren.
- [x] Exit-Code fuer interne Fehler definieren.
- [x] Maximal-Noise-Modus definieren.
- [x] Fail-Fast-Verhalten definieren.
- [x] Konfigurationsdatei einlesen koennen.

### GitHub und GitLab
- [x] GitHub Actions Workflow skizzieren.
- [x] GitLab CI Template skizzieren.
- [x] Token-basierte Authentifizierung definieren.
- [x] Artefakt-Upload definieren.
- [x] Comment-Bot-Verhalten definieren.
- [x] Deduplizierte PR-Kommentare definieren.

### PR-Kommentare
- [x] Finding-zu-File-Line-Mapping validieren.
- [x] Kommentarstil mit kurzer Zusammenfassung definieren.
- [x] Kommentarstil mit Remediation definieren.
- [x] Kommentarstil mit Severity definieren.
- [x] Wiederholte Kommentare unterdruecken.
- [x] Kommentare bei Baseline-Treffern unterdruecken.

### Policy Gates
- [x] Block-Regeln fuer Critical definieren.
- [x] Block-Regeln fuer High definieren.
- [x] Warn-Regeln fuer Medium definieren.
- [x] Projektweite Overrides definieren.
- [x] Branch-spezifische Regeln vorsehen.
- [x] Policy-Entscheidung im Report speichern.

### False-Positive-Management
- [x] Triaging-Status definieren.
- [x] Begruendungsfelder definieren.
- [x] Audit-Log fuer Entscheidungen definieren.
- [x] Suppressions befristet machen koennen.
- [x] Review-Flow fuer Suppressions festlegen.
- [x] Manuelle Override-Regeln unterstuetzen.

## P1 - Framework Awareness
### Node / Web
- [x] Express-Source-Sinks modellieren.
- [x] Next.js Request-Flows modellieren.
- [x] React DOM XSS-Floesse modellieren.
- [x] Middleware-basierte Auth-Checks modellieren.

### Python
- [x] Django Request-Flows modellieren.
- [x] Template-Rendering-Sinks modellieren.
- [x] ORM-Queries modellieren.
- [x] File-Access-Sinks modellieren.

### Java / Kotlin
- [x] Spring Request-Flows modellieren.
- [x] Servlet- und Controller-Einstiege modellieren.
- [x] SQL-Query-Sinks modellieren.
- [x] Deserialisierungssinks modellieren.

### PHP
- [x] Laravel Request-Flows modellieren.
- [x] Blade-Template-Sinks modellieren.
- [x] File- und Process-Sinks modellieren.

## P2 - Dataflow und Taint
### Quellen und Senken
- [x] User-Input-Quellen definieren.
- [x] Header-Quellen definieren.
- [x] Query-Parameter-Quellen definieren.
- [x] Body-Quellen definieren.
- [x] Cookie-Quellen definieren.
- [x] Auth-Context als Quelle oder Guard modellieren.

### Propagation
- [x] Zuweisungen propagieren.
- [x] Funktionsaufrufe propagieren.
- [x] Rueckgabewerte propagieren.
- [x] Container-Operationen propagieren.
- [x] Objektfelder propagieren.
- [x] Branches konservativ behandeln.

### Sanitizers und Guards
- [x] String-Escapes als Sanitizer modellieren.
- [x] Parameterisierte Queries als Sanitizer modellieren.
- [x] URL-Allowlisting als Guard modellieren.
- [x] Auth-Checks als Guard modellieren.
- [x] Rollenpruefungen als Guard modellieren.

### Reachability
- [x] Unerreichbare Sinks markieren.
- [x] Erreichbare Sinks priorisieren.
- [x] Pfadinformation im Finding speichern.
- [x] Kontext fuer Exploitbarkeit vorhalten.

## P2 - Mobile
### Android
- [x] Android Manifest lesen.
- [x] Exported Activities erkennen.
- [x] Exported Broadcast Receiver erkennen.
- [x] Dangerous Permissions erkennen.
- [x] Insecure SharedPreferences erkennen.
- [ ] Insecure SQLite-Nutzung erkennen.
- [ ] WebView-Risiken erkennen.
- [ ] Custom URL Scheme Risiken erkennen.

### iOS
- [ ] Entitlements lesen.
- [ ] ATS Fehlkonfigurationen erkennen.
- [ ] Keychain-Nutzung bewerten.
- [ ] URL Scheme Risiken erkennen.
- [ ] Insecure Logging erkennen.
- [ ] Jailbreak- und Hooking-Risiken ausweisen.

### Mobile allgemein
- [ ] Hardcoded Secrets in Mobile-Code erkennen.
- [ ] TLS- und Certificate-Checks bewerten.
- [ ] Debuggable Builds erkennen.
- [ ] Fehlende Obfuscation als Risiko ausweisen.
- [ ] Sensible Logs erkennen.

## P2 - Plattform
### API und Dashboard
- [ ] Scan-API definieren.
- [ ] Findings-API definieren.
- [ ] Projekt-API definieren.
- [ ] Dashboard-Datenmodell definieren.
- [ ] Trends pro Projekt berechnen.
- [ ] Severity- und Fix-Trends darstellen.

### Audit Trail
- [ ] Suppression-Historie speichern.
- [x] Policy-Entscheidungen speichern.
- [ ] Scan-Run-Metadaten speichern.
- [ ] Rule-Versionen speichern.
- [ ] Baseline-Referenzen speichern.

## P3 - Advanced
### Quality und Intelligence
- [ ] Exploitability-Score evaluieren.
- [ ] Attack-Path-Analyse evaluieren.
- [ ] Auto-Generated Tests evaluieren.
- [ ] AI-Assisted Remediation evaluieren.
- [ ] Secure Coding Training pro Finding evaluieren.

### Integrationen
- [ ] Jira-Integration evaluieren.
- [ ] Linear-Integration evaluieren.
- [ ] IDE-Integration evaluieren.
- [ ] MCP- oder Agent-API evaluieren.

### Erweiterungen
- [ ] IaC-Scanning als eigene Quelle ausbauen.
- [ ] Container-Scanning als eigene Quelle ausbauen.
- [ ] DAST-Anbindung als spaetere Stufe beschreiben.
- [ ] MAST-Anbindung als spaetere Stufe beschreiben.
- [ ] SBOM-Export integrieren.

## Checkliste fuer Release Readiness
- [ ] P0 komplett implementiert.
- [ ] P0 dokumentiert.
- [ ] P0 testbar.
- [ ] P1 CI-Flow laeuft.
- [ ] P1 PR-Kommentare validiert.
- [ ] P1 Baseline und Suppressions stabil.
- [ ] P2 nicht-blockierend geplant.
- [ ] P3 klar als spaeterer Ausbauschritt definiert.
