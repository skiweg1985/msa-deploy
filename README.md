# MSA – mDNS Service Atlas  
### *Discover. Map. Bridge.*

MSA ist ein verteiltes System zum Erfassen, Aufbereiten und Replizieren von mDNS-basierten Diensten (AirPlay, AirPrint, Sonos, Chromecast uvm.) über Netzwerk- und VLAN-Grenzen hinweg.

## Anwendungszweck

MSA ermöglicht es, mDNS-Services aus verschiedenen Netzwerken und VLANs zentral zu erfassen und gezielt in andere Netzwerke zu replizieren. Dies ist besonders nützlich für:

- **Multi-VLAN-Umgebungen**: Services aus einem VLAN in anderen VLANs verfügbar machen
- **Netzwerk-Segmentierung**: AirPlay, AirPrint und andere Services über Firewall-Grenzen hinweg nutzen
- **Zentrale Verwaltung**: Alle erkannten Services an einem Ort verwalten und konfigurieren
- **Service-Bridging**: AirGroup-ähnliche Funktionalität für beliebige mDNS-Services

## Architektur

MSA besteht aus zwei Komponenten:

- **Hub**: Zentrale Instanz, die Services von allen Satelliten sammelt und verwaltet
- **Satellite**: Lokale Agenten, die Services im Netzwerk erkennen und an den Hub melden

Satelliten können Services auch in konfigurierte Netzwerke/VLANs replizieren (Spoofing).

## Features

- **Service Discovery**: Automatische Erkennung von mDNS-Services (PTR, SRV, TXT, A, AAAA)
- **Zentrale Aggregation**: Alle Services von mehreren Satelliten in einer Registry
- **Service-Spoofing**: Replikation von Services in andere Netzwerke/VLANs
- **Web-UI**: React-basierte Benutzeroberfläche für Service-Verwaltung
- **Multi-Interface**: Unterstützung mehrerer Netzwerk-Interfaces pro Satellite

## Schnellstart

```bash
# Installation (im Monorepo msa-build aus dem Verzeichnis backend/)
cd backend
sudo ./install_msa.sh

# Hub oder Satellite installieren
# Wähle im Menü entsprechend

# Service-Status prüfen
sudo systemctl status mdns-hub
sudo systemctl status mdns-sat
```

### Lokaler Start ohne systemd (Entwicklung)

Voraussetzung ist die gemeinsame Python-venv unter `backend/venv` (z. B. über `install_msa.sh`, Menüpunkt **0) Nur venv / Python-Requirements installieren oder aktualisieren**).

- **Hub:** `./mdns-hub/run_hub.sh` — startet Uvicorn mit `main:app` auf **Port 8000** (abweichend vom systemd-Pfad über `main.py`, der standardmäßig **8080** nutzt).
- **Satellit:** `./mdns-sat/run_sat.sh` — führt `mdns_sat.py` mit der venv aus; die Sat-API/UI laeuft wie im installierten Betrieb standardmäßig auf **Port 8080**.

Nach der Installation:
1. Hub-Konfiguration anpassen: `mdns-hub/hub_config.yaml`
2. Satellite-Konfiguration anpassen: `mdns-sat/sat_config.yaml`
   - `sat_id`: Eindeutige ID
   - `hub_url`: URL des Hub-Servers
   - `shared_secret`: Authentifizierungs-Token

## Dokumentation

Detaillierte Informationen zur Installation, Konfiguration, Entwicklung und Troubleshooting finden Sie in [DOCUMENTATION.md](DOCUMENTATION.md).

## Hub Service-Filter-Defaults

Der Hub persistiert Include-Defaults fuer die Services-Ansicht jetzt in
`mdns-hub/data/hub_ui_settings.json` und stellt sie ueber
`GET/PUT /api/v1/ui/service-filters` bereit.

Semantik:
- `include_service_types: []` bedeutet bewusst: alle Services anzeigen.
- Verfuegbare UI-Optionen entstehen aus statischen Hub-Defaults plus im Hub beobachteten Service-Typen.
- SAT `excluded_services` bleibt davon getrennt und filtert weiter vor dem Hub-Ingest.

Breaking Change:
- Das fruehere Single-Select in `services.html` wurde durch Multi-Select mit Autocomplete ersetzt.
- Es gibt keine Migration alter lokaler `serviceType`-Filterzustände; die Hub-Defaults sind jetzt kanonisch.

## SAT Betriebsmodi (neu)

Der SAT kann jetzt ueber zwei Flags in `mdns-sat/sat_config.yaml` gesteuert werden:

- `publish_to_hub` (Default: `true`)
- `hub_register_enabled` (Default: `true`)

Matrix:
- `publish_to_hub=true`, `hub_register_enabled=true` -> **normal** (bisheriges Verhalten)
- `publish_to_hub=false`, `hub_register_enabled=true` -> **monitor_only** (lokales Sniffen/UI, keine Service-Publikation)
- `publish_to_hub=false`, `hub_register_enabled=false` -> **local_only** (komplett lokal, kein Hub-Register/Fetch/WS)
- `publish_to_hub=true`, `hub_register_enabled=false` -> **ungueltig** (Startabbruch/Failsafe)

Optional fuer `local_only`:
- `local_interfaces` als lokale Interface-Quelle, wenn keine Hub-Konfiguration genutzt wird.

Hinweis:
- `excluded_services` bleibt unveraendert aktiv und filtert weiterhin auf SAT-Seite vor Hub-Ingest.
- Die SAT-UI zeigt den aktiven Modus im Health-Bereich an.
