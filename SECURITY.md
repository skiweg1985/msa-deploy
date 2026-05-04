# Security-Übersicht: MSA (mDNS Satellite Architecture)

## Security-Haves (Aktuell implementiert)

### Authentifizierung SAT ↔ HUB

1. **Shared Secret Authentifizierung**
   - Statisches `shared_secret` in Hub- und Sat-Config
   - Verwendung für HTTP-Requests: Header `X-Satellite-Token`
   - Verwendung für WebSocket: Query-Parameter `token`
   - Verwendung bei Registrierung: Payload-Feld `auth_token`

2. **Geschützte API-Endpunkte**
   - `/api/v1/satellites/register` - Registrierung neuer Satelliten
   - `/api/v1/satellites/{sat_id}/config` (GET/PUT) - Config-Verwaltung
   - `/api/v1/satellites/{sat_id}/services` - Service-Ingest
   - `/api/v1/satellites/{sat_id}/spoofing` - Spoofing-Konfiguration
   - `/api/v1/satellites/{sat_id}/spoof-assignments` - Assignment-Abruf
   - WebSocket `/ws/sat` - Token-Validierung bei Verbindungsaufbau

3. **WebSocket-Sicherheit**
   - Token-Validierung beim Verbindungsaufbau
   - Connection wird bei ungültigem Token geschlossen (Code 1008)
   - `sat_id` wird aus Query-Parameter und Message-Body validiert

### Konfiguration

- Secret wird aus `hub_config.yaml` geladen (via `get_security_value()`)
- Fallback auf Default-Wert "changeme" wenn nicht konfiguriert
- Config-Dateien sollten mit entsprechenden Berechtigungen geschützt werden

---

## Offene Punkte / Security-Lücken

### 🔴 Kritisch

1. **Keine Verschlüsselung der Kommunikation**
   - Aktuell: HTTP/WS zwischen SAT und HUB (unverschlüsselt)
   - **Status**: SSL/TLS wird zukünftig am Load Balancer terminiert
   - **Offen**: 
     - Kommunikation zwischen LB und HUB (intern) bleibt unverschlüsselt
     - WebSocket-Upgrade von WSS zu WS am HUB (falls LB SSL terminiert)
     - Keine End-to-End-Verschlüsselung zwischen SAT und HUB

2. **Statisches Shared Secret**
   - Secret ist statisch und wird in Config-Dateien gespeichert
   - Keine Token-Rotation möglich
   - Keine Ablaufzeiten
   - **Risiko**: Bei Kompromittierung muss Secret manuell auf allen Satelliten geändert werden

3. **Keine gegenseitige Authentifizierung**
   - Nur SAT authentifiziert sich beim HUB
   - HUB authentifiziert sich nicht beim SAT
   - **Risiko**: Man-in-the-Middle-Angriffe möglich (wenn kein TLS)

4. **Ungeschützte API-Endpunkte**
   - `/api/v1/satellites` - Liste aller Satelliten (ohne Auth)
   - `/api/v1/services` - Liste aller Services (ohne Auth)
   - `/health` - Health-Check (ohne Auth, aber akzeptabel)
   - `/ui/*` - Web-UI-Endpunkte (ohne Auth)
   - **Risiko**: Sensible Informationen öffentlich zugänglich

5. **WebSocket-Token im Query-String**
   - Token wird als Query-Parameter übertragen (`?token=...`)
   - **Risiko**: 
     - Kann in Server-Logs, Proxy-Logs, Browser-History landen
     - Sichtbar in URL
     - Besser: Token im WebSocket-Header oder initialem Handshake

### 🟡 Wichtig

6. **CORS zu offen**
   - Aktuell: `allow_origins=["*"]` im Hub
   - **Risiko**: Jede Domain kann API aufrufen
   - **TODO**: In Production auf spezifische Origins einschränken

7. **Keine Rate Limiting**
   - Keine Begrenzung von API-Requests pro IP/Satellit
   - **Risiko**: DDoS, Brute-Force-Angriffe auf Token möglich
   - **TODO**: Rate Limiting für `/api/v1/satellites/register` und andere kritische Endpunkte

8. **Keine Audit-Logs**
   - Keine Logging von Authentifizierungsversuchen
   - Keine Logging von fehlgeschlagenen Token-Validierungen
   - **TODO**: Security-Event-Logging implementieren

9. **Keine Input-Validierung**
   - `sat_id` wird nicht auf Format/Inhalt validiert
   - Keine Längenbegrenzungen für Config-Werte
   - **Risiko**: Injection-Angriffe möglich

10. **Config-Dateien unverschlüsselt**
    - Secrets werden in Klartext in YAML-Dateien gespeichert
    - **TODO**: 
      - Secrets aus Environment-Variablen oder Secret-Management
      - Config-Dateien mit restriktiven Berechtigungen (600)

### 🟢 Verbesserungen

11. **Keine Zertifikats-basierte Authentifizierung**
    - Aktuell nur Shared Secret
    - **Zukunft**: Client-Zertifikate für SAT ↔ HUB Authentifizierung

12. **Keine Session-Management**
    - WebSocket-Verbindungen haben keine Session-IDs
    - Keine Möglichkeit, aktive Sessions zu invalidieren

13. **Keine Verschlüsselung der Persistenz**
    - Daten in `data/*.json` werden unverschlüsselt gespeichert
    - **Risiko**: Bei Dateisystem-Zugriff lesbar

14. **Keine Health-Check-Authentifizierung**
    - `/health` ist öffentlich (akzeptabel für Monitoring)
    - Aber: Keine Unterscheidung zwischen öffentlichem und internem Health-Check

15. **WebSocket-Protokoll**
    - Keine Message-Integritätsprüfung (außer JSON-Validierung)
    - Keine Replay-Schutz
    - Keine Sequenznummern für Nachrichten

---

## Empfohlene Maßnahmen für Production

### Kurzfristig (vor LB-Deployment)

1. **SSL/TLS am Load Balancer**
   - ✅ SSL-Terminierung am LB (geplant)
   - ⚠️ **Offen**: Interne Kommunikation LB → HUB absichern
   - ⚠️ **Offen**: WebSocket-Upgrade-Handling (WSS → WS)

2. **API-Endpunkte absichern**
   - `/api/v1/satellites` und `/api/v1/services` mit Authentifizierung schützen
   - Oder: IP-Whitelisting für interne Netzwerke

3. **CORS einschränken**
   - `allow_origins` auf spezifische Domains setzen
   - Keine Wildcards in Production

4. **Config-Sicherheit**
   - Secrets in Environment-Variablen
   - Config-Dateien mit `chmod 600` schützen
   - Secrets nicht in Git committen

### Mittelfristig

5. **Token-Rotation**
   - Automatische Rotation des Shared Secrets
   - Oder: JWT-basierte Authentifizierung mit Ablaufzeiten

6. **Rate Limiting**
   - Implementierung für kritische Endpunkte
   - Pro IP/Satellit begrenzen

7. **Audit-Logging**
   - Logging aller Authentifizierungsversuche
   - Logging von Config-Änderungen
   - Logging von Spoofing-Aktivierungen

8. **Input-Validierung**
   - Validierung von `sat_id` (Format, Länge)
   - Sanitization von Config-Werten

### Langfristig

9. **Zertifikats-basierte Authentifizierung**
   - Client-Zertifikate für SAT ↔ HUB
   - PKI-Integration

10. **End-to-End-Verschlüsselung**
    - TLS zwischen SAT und HUB (auch hinter LB)
    - Oder: Application-Level-Verschlüsselung

11. **Secret-Management**
    - Integration mit Vault, AWS Secrets Manager, etc.
    - Automatische Secret-Rotation

12. **WebSocket-Sicherheit verbessern**
    - Token im Header statt Query-String
    - Message-Integritätsprüfung
    - Replay-Schutz

---

## Kommunikation SAT ↔ HUB (Aktuell)

### HTTP-Requests (SAT → HUB)
- **Protokoll**: HTTP (unverschlüsselt)
- **Authentifizierung**: Header `X-Satellite-Token: <shared_secret>`
- **Endpunkte**:
  - `POST /api/v1/satellites/register`
  - `GET /api/v1/satellites/{sat_id}/config`
  - `POST /api/v1/satellites/{sat_id}/services`
  - `GET /api/v1/satellites/{sat_id}/spoof-assignments`

### WebSocket (SAT ↔ HUB)
- **Protokoll**: WS (unverschlüsselt) oder WSS (wenn HTTPS)
- **Authentifizierung**: Query-Parameter `?token=<shared_secret>&sat_id=<sat_id>`
- **Endpunkt**: `/ws/sat`
- **Nachrichten**: JSON, keine zusätzliche Verschlüsselung

### Nach LB-Deployment (SSL-Terminierung am LB)

**Erwartetes Setup:**
```
SAT (HTTPS/WSS) → Load Balancer (SSL-Terminierung) → HUB (HTTP/WS intern)
```

**Offene Fragen:**
1. Wie wird die interne Kommunikation LB → HUB abgesichert?
   - Option A: Vertrauen auf internes Netzwerk (nicht ideal)
   - Option B: TLS auch intern (mTLS empfohlen)

2. WebSocket-Upgrade-Handling:
   - LB muss WSS → WS konvertieren können
   - Oder: HUB muss WSS direkt unterstützen

3. X-Forwarded-* Headers:
   - LB sollte Original-IP an HUB weitergeben
   - Für Rate Limiting und Audit-Logs wichtig

---

## Checkliste für LB-Deployment

- [ ] SSL-Zertifikat am LB konfiguriert
- [ ] HUB erkennt X-Forwarded-For Header
- [ ] WebSocket-Upgrade funktioniert (WSS → WS)
- [ ] Interne Kommunikation LB → HUB abgesichert (mTLS oder internes Netzwerk)
- [ ] Health-Check-Endpunkt `/health` für LB konfiguriert
- [ ] CORS auf spezifische Origins eingeschränkt
- [ ] API-Endpunkte mit Authentifizierung geschützt
- [ ] Config-Dateien mit restriktiven Berechtigungen (600)
- [ ] Secrets aus Environment-Variablen geladen
- [ ] Rate Limiting aktiviert
- [ ] Audit-Logging implementiert
