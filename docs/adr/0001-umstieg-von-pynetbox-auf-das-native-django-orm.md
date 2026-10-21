---
number: 1
title: "Umstieg von pynetbox auf das native Django-ORM"
status: proposed
date: 2026-10-19
deciders: [Nico]
supersedes: null
superseded_by: null
tags: [persistenz, netbox, api]
plan: null
---

# ADR-0001: Umstieg von pynetbox auf das native Django-ORM

## Kontext und Problemstellung

Version v1.3 des Scripts lief auf NetBox 3.7 und sprach NetBox über `pynetbox`
(REST-API) an. Zwei Eigenschaften dieser Lösung waren problematisch:

1. Der API-Token war hartcodiert im Script hinterlegt.
2. Die TLS-Verifikation war deaktiviert (`verify=False`), damit die Verbindung
   zur internen Instanz überhaupt zustande kam.

Nach der Migration auf NetBox 4.6.4 erschien das Script nicht mehr in der UI
(`Automation → Scripts`). Ursache war unter anderem ein unvollständiger Import:
`BooleanVar` und `StringVar` wurden nicht aus `extras.scripts` importiert. Das
Script ist damit ein NetBox-*Custom Script*, das ohnehin im NetBox-Prozess läuft
und Zugriff auf die Django-ORM-Schicht hat.

## Entscheidungstreiber

- Kein Zugangsgeheimnis (Token) im Repository oder im Script-Code
- Kein HTTP-Overhead, wenn der Code ohnehin in-process läuft
- Weniger und besser pflegbare Abhängigkeiten (`networkscan` bleibt nötig)
- Kompatibilität mit dem Upload-Mechanismus für NetBox-Custom-Scripts
- Wartbarkeit des Forks gegenüber Upstream (`bbird81/Netbox-ipscanner`)

## Betrachtete Optionen

### Option A: pynetbox (REST-API) beibehalten

**Pro:** läuft auch außerhalb einer NetBox-Installation; die bestehende Logik musste nicht umgeschrieben werden.
**Contra:** Token-Handling und `verify=False` bleiben; jede Scan-Aktion ist ein HTTP-Roundtrip; die im Prozess bereits vorhandene Datenbankschicht bleibt ungenutzt; Query-Verhalten ist über die REST-API nicht kontrollierbar.

### Option B: natives Django-ORM innerhalb des Custom Scripts

**Pro:** kein Token, kein HTTP; direkter Zugriff auf `ipam.models` und `ipam.choices`; Query-Optimierung liegt in eigener Hand; Custom Scripts sind genau dafür vorgesehen.
**Contra:** nur innerhalb einer NetBox-Installation lauffähig; bindet das Script an die installierte NetBox-/Django-Version.

### Option C: REST-API direkt (requests) mit Token aus Umgebungsvariable

**Pro:** keine `pynetbox`-Abhängigkeit; läuft außerhalb von NetBox.
**Contra:** löst nur die Token-Hartcodierung, nicht den Overhead; der API-Vertrag müsste selbst gepflegt werden.

## Entscheidung

**Gewählt:** Option B — Umstellung auf das native Django-ORM.

**Begründung:** Das Script läuft als NetBox-Custom-Script ohnehin im
NetBox-Prozess. Jeder REST-Aufruf wäre ein vermeidbarer Umweg über das Netzwerk
zurück zu derselben Datenbank, und das Token-Problem verschwindet vollständig,
statt nur verwaltet zu werden. Die Inkompatibilität mit NetBox 4.6.4 ließ sich
nur innerhalb der Custom-Script-API sauber lösen (`log_failure` statt
`log_error`, korrekte `BooleanVar`/`StringVar`-Imports).

## Konsequenzen

### Positiv

- Keine Tokens oder hartcodierten URLs mehr im Code
- Status-Konstanten (`PrefixStatusChoices`, `IPAddressStatusChoices`) statt Status-Strings
- Batch-Abfragen ohne REST-Limitierungen möglich (siehe ADR-0002)
- Zwei Abhängigkeiten weniger (`pynetbox`, `ipcalc` entfallen)

### Negativ

- Das Script ist nicht mehr eigenständig lauffähig — es braucht eine NetBox-Installation
- Änderungen an internen NetBox-APIs (z. B. `log_error` → `log_failure` in 4.x) brechen das Script bei Versionssprüngen

### Risiken und Gegenmaßnahmen

| Risiko | Gegenmaßnahme |
|---|---|
| NetBox-Update bricht interne API-Aufrufe | README-Kompatibilitätstabelle, getestet gegen 4.6.4, produktiver Lauf erst nach Dry-Run |
| Der Fork driftet weiter von Upstream weg | Herkunft im README dokumentieren (Fork von `bbird81/Netbox-ipscanner`) |
| Script wird außerhalb NetBox gestartet | Imports schlagen sofort fehl; Deployment über UI-Upload, nicht Dateikopie |

## Links

- Code: `netbox_ipscanner.py:1-9` (Imports), `:12` (Klasse), `:182-192` (Transaktion)
- Commit: `37c8218` — *v2.0: Migrate to NetBox 4.6.x — native ORM, batch queries, dry-run*
- README: Kompatibilitätstabelle (4.6.x aktiv, 3.7 Legacy)
- Upstream: `bbird81/Netbox-ipscanner`

## Revision History

<!-- Wird von `adr.py edit N --correction "<Grund>"` befüllt. Eine inhaltliche
     Meinungsänderung gehört NICHT hierher, sondern in ein neues ADR mit
     `supersedes: 0001`. -->
