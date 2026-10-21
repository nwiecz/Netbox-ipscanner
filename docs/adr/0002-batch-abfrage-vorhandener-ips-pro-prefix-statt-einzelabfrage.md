---
number: 2
title: Batch-Abfrage vorhandener IPs pro Prefix statt Einzelabfragen
status: proposed
date: 2026-10-19
deciders: [Nico]
supersedes: null
superseded_by: null
tags: [performance, datenbank]
plan: null
---

# ADR-0002: Batch-Abfrage vorhandener IPs pro Prefix statt Einzelabfragen

## Kontext und Problemstellung

Für jeden Prefix muss festgestellt werden, welche IP-Adressen bereits im IPAM
eingetragen sind, um sie anschließend gegen die per ICMP gefundenen Hosts
abzugleichen (aktivieren, DNS-Namen aktualisieren, nicht antwortende Adressen
deprecaten). Ein naiver Aufbau fragt pro Adresse einzeln ab — das erzeugt
N+1-Queries: bei einem /22-Prefix mit 1022 Hosts sind das bis zu 1022
Datenbankabfragen **pro Prefix**, und das Script läuft über alle Prefixe
(`job_timeout = 3600`).

## Entscheidungstreiber

- Laufzeit des Scans bei vielen Prefixen und großen Subnetzen
- Last auf der NetBox-Datenbank (NetBox wird parallel benutzt)
- Lesbarkeit: der Set-Abgleich (alive vs. vorhanden) soll an einer Stelle stehen
- Kein zusätzliches Caching oder externer Store (YAGNI)

## Betrachtete Optionen

### Option A: Einzelabfrage je Adresse im Schleifenkörper

**Pro:** trivial zu schreiben, sofort verständlich.
**Contra:** N+1-Queries; Laufzeit und Datenbanklast skalieren linear mit der Hostzahl — bei großen Prefixen untragbar.

### Option B: Eine Batch-Abfrage je Prefix mit `address__net_contained_or_equal`

**Pro:** 1 Query pro Prefix statt N; NetBox filtert serverseitig über den im Datenmodell hinterlegten Netzbereich; das Ergebnis wird direkt zum Dict für den Set-Abgleich.
**Contra:** ein Query auch dann, wenn im Prefix gar keine Hosts hängen; setzt Kenntnis des NetBox-ORM-Filters voraus.

### Option C: Alle IPs aller Prefixe einmalig laden und im Speicher filtern

**Pro:** genau eine Query für den gesamten Lauf.
**Contra:** lädt die komplette IPAM-Tabelle in den Speicher — bei Installationen mit Zehntausenden Adressen unnötig teuer, und das Script läuft im NetBox-Webprozess.

## Entscheidung

**Gewählt:** Option B — `IPAddress.objects.filter(address__net_contained_or_equal=str(prefix.prefix))` einmal pro Prefix, Ergebnis als Dict `{ip_ohne_maske: IPAddress}`.

**Begründung:** Die Query-Zahl sinkt von O(Hosts) auf O(Prefixe), ohne die
gesamte IPAM-Tabelle in den Speicher zu laden. Genau ein Query pro Prefix liefert
alles, was der Listenvergleich braucht: in NetBox ist die Adresse als
`10.0.0.1/24` gespeichert, der Scan liefert `10.0.0.1` — die Maske wird beim
Aufbau des Dicts einmal entfernt, danach ist der Vergleich ein `in`-Test gegen
ein Set.

## Konsequenzen

### Positiv

- Eine Datenbankabfrage pro Prefix statt einer pro Hostadresse
- Die Set-Logik (`alive_hosts` vs. `existing_ips`) ist kurz und lokal nachvollziehbar
- Der Filter bleibt auch bei großen Netzen serverseitig effizient

### Negativ

- `net_contained_or_equal` ist NetBox-ORM-spezifisch und muss bei NetBox-Upgrades mitgeprüft werden
- Die Masken-Konvention (`/24` beim Speichern, ohne Maske beim Vergleich) muss beim nächsten Datenzugriff im Script bekannt sein

### Risiken und Gegenmaßnahmen

| Risiko | Gegenmaßnahme |
|---|---|
| `net_contained_or_equal` verhält sich in einer neueren NetBox-Version anders | Kompatibilitätstabelle im README, Dry-Run vor dem produktiven Lauf |
| Sehr große Prefixe mit vielen Einträgen | Reserved- und Container-Prefixe werden übersprungen; Tag-Filter erlaubt die Beschränkung auf relevante Subnetze |
| Adressformat im Feld ändert sich | Masken-Parsing an genau einer Stelle (`_get_existing_ips`) |

## Links

- Code: `netbox_ipscanner.py:45-60` (`_get_existing_ips`), `:128-130` (Aufruf, `alive_hosts`)
- Commit: `37c8218`

## Revision History

<!-- Wird von `adr.py edit N --correction "<Grund>"` befüllt. Eine inhaltliche
     Meinungsänderung gehört NICHT hierher, sondern in ein neues ADR mit
     `supersedes: 0002`. -->
