---
number: 3
title: "Dry-Run über commit=False und Schreibvorgänge in einer Transaktion"
status: proposed
date: 2026-10-19
deciders: [Nico]
supersedes: null
superseded_by: null
tags: [betrieb, datenkonsistenz]
plan: null
---

# ADR-0003: Dry-Run über commit=False und Schreibvorgänge in einer Transaktion

## Kontext und Problemstellung

Ein Scan verändert das IPAM: nicht antwortende Adressen werden auf
`deprecated` gesetzt, DNS-Namen überschrieben, neue Adressen angelegt. Ein
Fehlschlag mitten im Lauf (falsche Route, Firewall blockt ICMP, falscher
Tag-Filter) konnte in v1.x einen Prefix flächig auf *deprecated* setzen, bevor
jemand den Lauf abbrechen konnte. NetBox-Custom-Scripts bekommen vom Framework
einen `commit`-Parameter, der genau dieses Problem adressiert.

## Entscheidungstreiber

- Kein Datenverlust bei einem Testlauf — erst prüfen, dann schreiben
- Konsistenz: ein Prefix wird ganz oder gar nicht aktualisiert
- Sichtbarkeit: aus dem Job-Log muss erkennbar sein, was *passieren würde*
- Wenig Komplexität im Script selbst (keine eigenen Staging-Tabellen)

## Betrachtete Optionen

### Option A: Immer schreiben, Rücknahme über Datenbank-Backup

**Pro:** ein Codepfad weniger.
**Contra:** jede Prüfung braucht ein Restore; nicht praktikabel und für den Betreiber riskant.

### Option B: `commit=False` als Dry-Run plus `transaction.atomic()` im Schreibpfad

**Pro:** das NetBox-Framework liefert den Schalter bereits; ein Testlauf schreibt nichts (nur `[DRY-RUN]`-Logzeilen); im Schreibpfad sind Updates und Anlagen eines Prefix atomar.
**Contra:** zwei Codepfade nebeneinander; der Dry-Run-Pfad muss bei neuen Änderungstypen mitgezogen werden.

### Option C: Erst in eine Schattenstruktur schreiben, dann promoten

**Pro:** maximale Kontrolle.
**Contra:** braucht zusätzliches Datenmodell und Aufräumlogik — unverhältnismäßig für ein einzelnes Custom Script.

## Entscheidung

**Gewählt:** Option B — Dry-Run über den `commit`-Parameter, Schreibvorgänge gebündelt in `with transaction.atomic():`.

**Begründung:** Das Framework liefert die Sicherheitsmechanik, und der Aufwand
besteht nur darin, den Schreibpfad tatsächlich hinter `if commit:` zu stellen.
Ein Prefix wird geändert oder gar nicht — ein halb aktualisierter Prefix kann
nicht entstehen. Einzelne Anlagefehler (z. B. Dublette) werden im
Transaktionsblock protokolliert, statt den gesamten Lauf zu beenden.

## Konsequenzen

### Positiv

- Produktive Läufe sind ohne Risiko vorprüfbar; das Job-Log zeigt geplante Änderungen
- Teilweise aktualisierte Prefixe sind ausgeschlossen
- Fehler bei einzelnen Adressen brechen den Lauf nicht ab

### Negativ

- Der Dry-Run-Pfad ist ein zweiter Codepfad und veraltet still, wenn neue Änderungstypen ihn nicht bedienen
- `transaction.atomic()` gilt pro Prefix, nicht über den ganzen Lauf — ein Lauf über mehrere Prefixe ist nicht global atomar
- `job_timeout = 3600` bleibt eine Betriebsgrenze, die der Dry-Run-Pfad nicht verkürzt

### Risiken und Gegenmaßnahmen

| Risiko | Gegenmaßnahme |
|---|---|
| Dry-Run wird als Bestätigung missverstanden und produktiv übersprungen | Deployment-Schritte im README: erst Dry-Run, dann `commit=True` |
| Neuer Änderungstyp fehlt im Dry-Run-Pfad | Beim Ergänzen beider Pfade im selben Commit; Review-Checkliste im README |
| Lauf bricht nach halbem Weg ab | Atomarität pro Prefix begrenzt den Schaden; Job-Log zeigt den letzten erfolgreichen Prefix |

## Links

- Code: `netbox_ipscanner.py:182-198` (Transaktion und Dry-Run-Zweig), `:32` (`job_timeout`)
- Commit: `37c8218`
- README: Deployment-Schritte (Dry-Run vor `commit=True`)

## Revision History

<!-- Wird von `adr.py edit N --correction "<Grund>"` befüllt. Eine inhaltliche
     Meinungsänderung gehört NICHT hierher, sondern in ein neues ADR mit
     `supersedes: 0003`. -->
