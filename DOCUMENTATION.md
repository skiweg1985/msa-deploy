# MSA Dokumentation

Detaillierte Dokumentation für Installation, Konfiguration, Entwicklung und Troubleshooting.

## Installation

### Voraussetzungen
- Python 3.8+
- Ubuntu/Debian oder Raspberry Pi OS
- Root-Rechte für Installation
- Netzwerk-Zugriff zwischen Hub und Satelliten

### Hub-Installation

```bash
cd msa
sudo ./install_msa.sh
# Wähle "Hub installieren"
```

Das Script:
- Installiert Python-Abhängigkeiten in gemeinsames `venv`
- Erstellt systemd-Service `mdns-hub.service`
- Kopiert `mdns-hub/hub_config.example.yaml` zu `mdns-hub/hub_config.yaml`
- Startet den Hub-Service

**Konfiguration**: Bearbeite `mdns-hub/hub_config.yaml` nach Installation.

### Satellite-Installation

```bash
cd msa
sudo ./install_msa.sh
# Wähle "Sat installieren"
```

Das Script:
- Installiert Python-Abhängigkeiten
- Erstellt systemd-Service `mdns-sat.service`
- Kopiert `mdns-sat/example.sat_config.yaml` zu `mdns-sat/sat_config.yaml`
- Startet den Sat-Service

**Konfiguration**: Bearbeite `mdns-sat/sat_config.yaml`:
- `sat_id`: Eindeutige ID des Satelliten
- `hub_url`: URL des Hub-Servers
- `shared_secret`: Authentifizierungs-Token (muss mit Hub übereinstimmen)

### Service-Management

```bash
# Service-Status prüfen
sudo systemctl status mdns-hub
sudo systemctl status mdns-sat

# Service neu starten
sudo systemctl restart mdns-hub
sudo systemctl restart mdns-sat

# Logs anzeigen
sudo journalctl -u mdns-hub -f
sudo journalctl -u mdns-sat -f
```

## Konfiguration

### Hub-Konfiguration (`mdns-hub/hub_config.yaml`)

```yaml
logging:
  root_level: INFO
  mdns_hub_level: INFO

security:
  shared_secret: "supergeheim"  # Muss mit Satelliten übereinstimmen

ui:
  service_filters:
    # Initiale Include-Defaults fuer die Hub-Services-UI.
    # Diese Defaults werden verwendet, bis der Hub eine explizite
    # Auswahl nach data/hub_ui_settings.json gespeichert hat.
    default_include_service_types:
      - "_airplay._tcp.local"
      - "_ipp._tcp.local"
```

### Satellite-Konfiguration (`mdns-sat/sat_config.yaml`)

**Basis-Konfiguration:**
```yaml
sat_id: "satellite-01"
hub_url: "http://192.168.1.100:8080"
shared_secret: "supergeheim"
publish_to_hub: true
hub_register_enabled: true
```

**Interface-Konfiguration:**
- Wird vom Hub verwaltet (über `/api/v1/satellites/{sat_id}/config`)
- Definiert welche Interfaces für Discovery/Spoofing verwendet werden
- Modes: `sniff_only`, `scan`, `advertise`, `scan_and_advertise`

**Service-Filter:**
```yaml
excluded_services:
  - "_remotepairing._tcp.local"
  - "_companion-link._tcp.local"
  - "_sleep-proxy._udp.local"
```

Abgrenzung:
- `excluded_services` wirkt auf dem Sat vor dem Hub-Ingest.
- Ein dort ausgeschlossener Service erscheint im Hub nie.
- Hub-UI-Include-Defaults filtern spaeter nur bereits ingestierte Service-Typen in der Hub-Ansicht.

**SAT Betriebsmodi:**
- `publish_to_hub=true`, `hub_register_enabled=true` -> normal (Standard)
- `publish_to_hub=false`, `hub_register_enabled=true` -> `monitor_only`
  - Discovery + SAT-UI aktiv
  - kein Service-Publish (HTTP/WS) zum Hub
- `publish_to_hub=false`, `hub_register_enabled=false` -> `local_only`
  - kein Hub-Register, kein Hub-Config-Fetch, kein Hub-WS
  - komplett lokaler Betrieb
- `publish_to_hub=true`, `hub_register_enabled=false` -> ungueltig (Startabbruch)

**Local-only Interface-Quelle:**
```yaml
local_interfaces:
  - name: "eth0"
    vlan_id: 0
    mode: "scan"
```
Ohne Hub-Konfiguration kann `local_interfaces` als lokale Quelle fuer SAT-Interfaces genutzt werden.

**Spoofing-Konfiguration:**
- TTL-Werte für verschiedene Record-Typen
- Burst-Einstellungen für Announcements
- Refresh-Intervalle

## Projektstruktur

```
msa/
├── mdns-hub/              # Hub-Komponente
│   ├── main.py           # FastAPI-App, API-Endpoints
│   ├── models.py         # Pydantic-Models
│   ├── templates/        # HTML-Templates (Legacy-UI)
│   ├── frontend/         # React-Build-Output
│   └── hub_config.yaml   # Hub-Konfiguration
│
├── mdns-sat/             # Satellite-Komponente
│   ├── mdns_sat.py       # Haupt-Script, FastAPI-Server
│   ├── mdns_utils.py     # Service-Cache, Snapshot-Building
│   ├── mdns_worker.py    # Interface-Worker für mDNS
│   ├── mdns_query_handler.py  # Query-Handling
│   ├── mdns_resolver.py  # Service-Resolution
│   ├── ui.html           # Lokale Web-UI
│   └── sat_config.yaml   # Satellite-Konfiguration
│
├── install_msa.sh        # Installations-Script
├── manage_services.py    # systemd-Service-Management
└── README.md
```

## Entwicklung

### Lokale Entwicklung

**Hub:**
```bash
cd mdns-hub
../venv/bin/uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```

**Satellite:**
```bash
cd mdns-sat
../venv/bin/python mdns_sat.py
```

### Frontend-Entwicklung

Das Frontend wird separat entwickelt (siehe `msa-frontend/`):
- React + TypeScript
- Vite als Build-Tool
- Tailwind CSS + shadcn/ui
- Build-Output wird in `mdns-hub/frontend/dist/` kopiert

### API-Endpoints

**Hub:**
- `GET /api/v1/services` - Liste aller Services
- `GET /api/v1/ui/service-filters` - Aktuelle Hub-UI-Include-Defaults und verfuegbare Service-Typen
- `PUT /api/v1/ui/service-filters` - Hub-UI-Include-Defaults persistent speichern
- `POST /api/v1/satellites/{sat_id}/services` - Service-Ingest
- `GET /api/v1/satellites/{sat_id}/config` - Satellite-Config
- `POST /api/v1/services/spoof` - Spoofing-Konfiguration

**Satellite:**
- `GET /services` - Lokale Service-Liste
- `GET /health` - Status-Informationen
- `GET /ui` - Lokale Web-UI

## Verwendung

### Service-Discovery

1. **Satelliten erkennen Services** im lokalen Netzwerk
2. **Services werden an Hub gemeldet** (wenn auf reporting interface gesehen)
3. **Hub aggregiert Services** von allen Satelliten
4. **Web-UI zeigt alle Services** mit Filter- und Suchfunktionen

### Service-Spoofing

1. **Service im Hub auswählen** und Spoofing aktivieren
2. **Targets konfigurieren**: Satellite → Interface(s) → VLAN(s)
3. **Satellite repliziert Service** in konfigurierte Netzwerke
4. **Vollständiger mDNS-Stack**: PTR, SRV, TXT, A, AAAA Records

### Filterung

Services werden automatisch gefiltert:
- **Excluded Services**: Konfigurierte Service-Typen werden ignoriert
- **Reverse-DNS-Namen**: Services mit `.in-addr.arpa` oder `.ip6.arpa` werden nicht gemeldet
- **Reporting Interfaces**: Nur Services von konfigurierten Interfaces werden gemeldet

Hub-Services-UI:
- Die Include-Auswahl ist jetzt ein Multi-Select mit Autocomplete.
- Eine leere Include-Liste bedeutet explizit: keine Einschraenkung, alle Services anzeigen.
- Die Hub-API persistiert diese Defaults in `mdns-hub/data/hub_ui_settings.json`.

### Breaking Changes

- Das bisherige Single-Select-Verhalten der Services-UI wurde entfernt.
- Es gibt keinen Kompatibilitaetspfad fuer alte lokale `serviceType`-Filterzustände aus dem Browser.
- Das kanonische Format fuer Hub-UI-Defaults ist jetzt `include_service_types: string[]`.

## Troubleshooting

### Service wird nicht erkannt
- Prüfe ob Service auf reporting interface gesehen wurde
- Prüfe `excluded_services` in Config
- Prüfe Logs: `journalctl -u mdns-sat -f`

### Service wird nicht an Hub gemeldet
- Prüfe Hub-Verbindung: `curl http://hub-url:8080/health`
- Prüfe `shared_secret` in beiden Configs
- Prüfe ob Service auf reporting interface gesehen wurde
- Prüfe Satellite-UI: `http://satellite-ip:8010/ui` (Spalte "Hub")

### Spoofing funktioniert nicht
- Prüfe ob Spoofing im Hub aktiviert ist
- Prüfe ob Targets korrekt konfiguriert sind
- Prüfe ob Interface-Mode `advertise` oder `scan_and_advertise` ist
- Prüfe Logs auf Fehlermeldungen

### Hub/Satellite startet nicht
- Prüfe Config-Dateien auf Syntax-Fehler
- Prüfe Logs: `journalctl -u mdns-hub -n 50`
- Prüfe ob Port bereits belegt ist
- Prüfe Python-Umgebung: `../venv/bin/python --version`
