#!/usr/bin/env bash
set -euo pipefail

echo "=== mDNS Hub Setup (Ubuntu/Debian) ==="

if [[ "$EUID" -ne 0 ]]; then
  echo "Bitte als root ausführen (sudo)."
  exit 1
fi

# -----------------------------------------------------------------------------
# Basis: Pfad zum Repo (msa) = Ordner, in dem dieses Script liegt
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
HUB_DIR="$SCRIPT_DIR/mdns-hub"

if [[ ! -d "$HUB_DIR" ]]; then
  echo "Fehler: Verzeichnis '$HUB_DIR' nicht gefunden."
  echo "Bitte das Repo 'msa' mit Unterordner 'mdns-hub' verwenden."
  exit 1
fi

# -----------------------------------------------------------------------------
# Konfiguration: eigener Systemuser ja/nein
# -----------------------------------------------------------------------------
USE_DEDICATED_USER=true      # auf false setzen, wenn du KEINEN Extra-User willst
HUB_USER="mdnshub"

# -----------------------------------------------------------------------------
# Pakete installieren
# -----------------------------------------------------------------------------
echo "[1/4] apt update & Grundpakete installieren..."
apt update
apt install -y python3 python3-venv python3-pip git curl

# -----------------------------------------------------------------------------
# User / Besitzer bestimmen
# -----------------------------------------------------------------------------
RUN_AS_USER="root"

if [[ "$USE_DEDICATED_USER" == true ]]; then
  echo "[2/4] Systemuser $HUB_USER prüfen/anlegen..."
  if ! id "$HUB_USER" >/dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin "$HUB_USER"
  fi
  RUN_AS_USER="$HUB_USER"
  chown -R "$HUB_USER":"$HUB_USER" "$HUB_DIR"
else
  # Falls du später lieber unter einem normalen Benutzer startest:
  RUN_AS_USER="$(logname 2>/dev/null || echo root)"
  echo "[2/4] Kein eigener Systemuser. Verwende Benutzer: $RUN_AS_USER"
fi

# -----------------------------------------------------------------------------
# Python Virtualenv im Repo-/Hub-Ordner anlegen
# -----------------------------------------------------------------------------
echo "[3/4] Python Virtualenv in $HUB_DIR anlegen..."
cd "$HUB_DIR"

sudo -u "$RUN_AS_USER" python3 -m venv venv
sudo -u "$RUN_AS_USER" ./venv/bin/pip install --upgrade pip

echo "[4/4] Benötigte Python-Pakete installieren..."
sudo -u "$RUN_AS_USER" ./venv/bin/pip install \
  fastapi \
  "uvicorn[standard]" \
  pydantic \
  jinja2 \
  python-multipart

echo ""
echo "FERTIG. mDNS Hub Umgebung ist eingerichtet."
echo "Repo-Basis: $SCRIPT_DIR"
echo "Hub-Verzeichnis: $HUB_DIR"
echo ""
echo "Teststart (als $RUN_AS_USER):"
echo "  cd $HUB_DIR"
echo "  sudo -u $RUN_AS_USER ./venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000"
echo ""
echo "Später können wir dafür eine systemd-Unit 'mdns-hub.service' bauen."