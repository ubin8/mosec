# MoSec P0 Implementation Backlog

## Ziel
P0 ist die erste technisch umsetzbare Version des CLI-Scanners. Hier stehen nur die Bausteine, die fuer einen ersten echten Scan-Workflow noetig sind: Repository-Ingestion, Datei- und Sprach-Erkennung, Parser-Schnittstelle, Regel- und Finding-Modell, Secrets, SCA, einfache Web-Regeln, Baseline, Suppressions und Exporte.

## Annahmen
- Python ist der primaere CLI- und Orchestrierungs-Stack.
- TOML ist das bevorzugte Konfigurationsformat fuer das CLI.
- JSON und SARIF sind die ersten Maschinenformate.
- Rust bleibt in P0 nur als vorbereitete Zielrichtung, nicht als harte Abhaengigkeit.

## 0. Projektfundament
- [x] Python-Paketstruktur im `src/`-Layout anlegen.
- [x] CLI-Entry-Point als `mosec` Befehl festlegen.
- [x] `python -m appsec_cli` als alternativen Einstieg bereitstellen.
- [x] Rust-Workspace als separates Zukunftsmodul anlegen.
- [x] Smoke-Test-Struktur fuer Python vorbereiten.
- [x] Installationsanleitung fuer Development-Setup schriftlich fixieren.
- [x] Laufzeitvoraussetzungen fuer Python 3.11+ dokumentieren.
- [x] Versionsschema fuer CLI und Rule-Packs festlegen.
- [x] Fehlercodes fuer CLI-Kommandos definieren.

## 1. CLI-Grundgeruest
- [x] `scan` als erstes Hauptkommando finalisieren.
- [x] `version` als neutrales Diagnosekommando behalten.
- [x] `--format` fuer Text und JSON implementieren.
- [x] `--help`-Ausgabe mit Beispielnutzung pruefen.
- [x] Exit-Code fuer erfolgreichen Scan definieren.
- [x] Exit-Code fuer Policy-Verletzungen definieren.
- [x] Exit-Code fuer interne Laufzeitfehler definieren.
- [x] Globale Optionen fuer `--config`, `verbose` und `quiet` vorsehen.
- [x] Struktur fuer spaetere Subcommands wie `baseline` und `triage` vorbereiten.

## 2. Konfiguration und Scan-Kontext
- [x] TOML-Konfigurationsschema definieren.
- [x] Default-Konfiguration mit sinnvollen Pfaden bereitstellen.
- [x] `root`, `include` und `exclude` aus Konfiguration laden.
- [x] CLI-Argumente mit Konfigurationswerten mergen.
- [x] Prioritaetsregel fuer CLI vs. Config dokumentieren.
- [x] Scan-Kontext-Objekt fuer Root, Regeln, Format und Filter einfueren.
- [x] Sanity-Checks fuer nicht existierende Pfade einbauen.
- [x] Konfigurationsfehler als user-friendly Fehler ausgeben.

## 3. Repository-Ingestion
- [x] Verzeichnis-Scan rekursiv implementieren.
- [x] Einzeldatei-Scan separat unterstuetzen.
- [x] Symlinks bewusst behandeln und dokumentieren.
- [x] Generierte Artefakte via Default-Excludes filtern.
- [x] Binaerdateien ueber Inhaltsprobe oder Endung aussortieren.
- [x] Leere Dateien erkennen und ignorieren.
- [x] Pfade vor dem Scan normalisieren.
- [x] Relevante Dateilisten als Scan-Work-Items erzeugen.
- [x] Scan-Statistiken fuer gesehen und selektiert speichern.
- [x] Abbruchverhalten bei Lesefehlern pro Datei definieren.

## 4. Sprach- und Framework-Erkennung
- [x] Primere Erkennung ueber Dateiendung implementieren.
- [x] Sekundaere Heuristiken fuer typische Manifest- und Config-Dateien ergaenzen.
- [x] Sprache pro Datei im File-Record speichern.
- [x] Framework-Hinweise aus Ordnernamen und Dateien ableiten.
- [x] Web-Stack und Mobile-Stack getrennt kennzeichnen.
- [x] Unbekannte Sprachen als `unsupported` markieren statt abbrechen.
- [x] Erkennungslogik testbar und austauschbar halten.
- [x] Erkennungsergebnisse im Scan-Report ausweisbar machen.

## 5. Parser-Schnittstelle
- [x] Parser-Interface als Python-Abstraktion definieren.
- [x] Parser-Input als Dateiinhalt plus Metadaten modellieren.
- [x] Parser-Output als AST- oder Token-Container modellieren.
- [x] Syntaxfehler als Diagnostics statt als Crash behandeln.
- [x] Parser-Implementierung pro Sprache als Modulgrenze vorsehen.
- [x] Fallback-Parser fuer reine Pattern-Regeln definieren.
- [x] Parser-Registry fuer spaeteres Plugin-Loading vorbereiten.
- [x] Parser-Fehler in Findings oder Warnungen ueberfuehren koennen.

## 6. IR und Findings-Modell
- [x] Gemeinsames Location-Modell fuer Datei, Zeile, Spalte definieren.
- [x] Gemeinsames Finding-Modell mit ID, Rule, Severity und Confidence definieren.
- [x] Evidence-Snippets mit Kontextzeilen speichern.
- [x] Code-Symbol-Referenzen im Finding-Schema vorsehen.
- [x] Finding-Deduplizierung ueber Rule plus Location vorbereiten.
- [x] Finding-Status fuer neu, bestaetigt, suppressed und baseline-definiert einbauen.
- [x] Einfaches IR fuer Calls, Assignments, Literale und Member-Zugriffe definieren.
- [x] IR so klein wie moeglich halten, damit sie spaeter erweiterbar bleibt.

## 7. Rule-Modell und Rule-Loading
- [x] Rule-Schema mit ID, Name, Kategorie und Beschreibung definieren.
- [x] OWASP- und CWE-Mapping pro Rule vorsehen.
- [x] Severity-Default pro Rule festlegen.
- [x] Confidence-Default pro Rule festlegen.
- [x] Zielsprachen pro Rule festlegen.
- [x] Rule-Packs als externe Dateien laden koennen.
- [x] Rule-Validation beim Laden einbauen.
- [x] Beispielcode oder Positive/Negative-Patterns pro Rule vorsehen.
- [x] Regelversionen im Report ausgeben koennen.

## 8. Output und Reporting
- [x] Textreport mit kurzer Zusammenfassung erzeugen.
- [x] JSON-Report als maschinenlesbares Vollformat erzeugen.
- [x] SARIF-Export fuer CI und Code-Hosts erzeugen.
- [x] Report-Metadaten mit Scan-Zeit, Root und Tool-Version ausgeben.
- [x] Findings nach Severity und Pfad sortieren koennen.
- [x] Deduplizierte Ausgabe sicherstellen.
- [x] Report-Renderer als eigene Schicht von der Analyse trennen.
- [x] Basis-Felder fuer spaetere HTML- oder API-Ausgaben mitfuehren.

## 9. Secrets-Scanning
- [x] Secret-Typen fuer API Keys, Tokens und Private Keys definieren.
- [x] Pattern-basierte Erkennung pro Secret-Typ implementieren.
- [x] Kontext-Heuristiken zur False-Positive-Reduktion einbauen.
- [x] Testwerte und Dummy-Secrets erkennen und unterdruecken.
- [x] Secret-Findings mit Maskierung und Klartext-Hinweis ausgeben.
- [x] Sensible Dateien wie `.env` und Config-Dumps priorisiert behandeln.
- [x] Ergebnisse mit Severity und Confidence klassifizieren.
- [x] Secret-Regeln als eigenstaendige Rule-Gruppe fuehren.

## 10. Dependency-Analyse / SCA
- [x] Manifestdateien pro Zielstack identifizieren.
- [x] Lockfiles pro Zielstack identifizieren.
- [x] Paketname, Version und Quelle extrahieren.
- [x] Direkt- und Transitivreferenzen unterscheiden.
- [x] Vulnerability-Datenquelle als austauschbares Backend abstrahieren.
- [x] CVE- oder Advisory-Matches in Findings ueberfuehren.
- [x] Keine Treffer von unbekannten Pakettypen als Fehler behandeln.
- [x] SCA-Ergebnisse im selben Finding-Format ausgeben.

## 11. Erste Web-Regeln
- [x] SQL-Injection-Sinks modellieren.
- [x] XSS-Sinks modellieren.
- [x] SSRF-Sinks modellieren.
- [x] Path-Traversal-Sinks modellieren.
- [x] Open-Redirect-Sinks modellieren.
- [x] Auth-Check-Abwesenheit als eigene Regelfamilie modellieren.
- [x] Einfache source-to-sink-Ketten ohne volles Tainting pruefen.
- [x] Erste Web-Regeln mit klaren Remediation-Hinweisen ausstatten.

## 12. Baseline und Suppressions
- [x] Baseline-Dateiformat definieren.
- [x] Baseline mit aktuellen Findings abgleichen.
- [x] Neue Findings von bereits bekannten Findings trennen.
- [x] Suppression-Kommentare oder Suppression-Dateien unterstuetzen.
- [x] Suppression-Gruende als Pflichtfeld einfuehren.
- [x] Suppressions mit Zeitstempel und Benutzerkontext speichern koennen.
- [x] Unterdrueckte Findings im Report sichtbar, aber nicht blockierend ausgeben.

## 13. Test- und Fixture-Basis
- [x] Mini-Repositorys fuer jede Zielkategorie anlegen.
- [x] Fixture fuer Secrets-Scanning anlegen.
- [x] Fixture fuer SCA-Metadaten anlegen.
- [x] Fixture fuer SQLi- und XSS-Regeln anlegen.
- [x] Fixture fuer Baseline und Suppression anlegen.
- [x] Smoke-Test fuer `scan` Command anlegen.
- [x] JSON-Ausgabe gegen Schema-Hinweise pruefen.
- [x] SARIF-Ausgabe auf minimale Gueltigkeit pruefen.

## 14. P0-Release-Kriterien
- [x] CLI kann ein lokales Repository scannen.
- [x] Mindestens eine Regel pro Kategorie `Secrets`, `SCA` und `Web-SAST` existiert.
- [x] JSON und SARIF funktionieren.
- [x] Baseline und Suppressions sind operational.
- [x] Fehlerszenarien brechen den Scan nicht global ab.
- [x] Die Ergebnisse sind fuer CI nutzbar.
- [x] Der Kern ist bereit fuer spaetere Rust-Auslagerung.
